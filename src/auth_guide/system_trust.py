"""Modular integration with supported local system trust stores."""

from __future__ import annotations

import asyncio
import platform
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from anyio import Path

from auth_guide.platform_trust.common import CommandResult

TrustStoreOverride = Literal["auto", "macos", "debian", "redhat"]


class SystemTrustStore(Protocol):
    """Install and remove a public CA certificate from one system trust store."""

    @property
    def name(self) -> str:
        """The stable implementation name."""

    async def install_certificate(self, certificate_pem: str) -> None:
        """Install the supplied public root certificate."""

    async def verify_certificate_absent(self, certificate_pem: str, *, certificate_fingerprint: str) -> None:
        """Confirm a root is absent before a privileged installation."""

    async def uninstall_certificate(self, certificate_pem: str, *, certificate_fingerprint: str | None = None) -> None:
        """Remove the supplied public root certificate."""


class TrustStoreError(RuntimeError):
    """Base error for system trust integration failures."""


class UnsupportedTrustStoreError(TrustStoreError):
    """Raised when automatic selection cannot identify a supported store."""


@dataclass(frozen=True, slots=True)
class SubprocessCommandRunner:
    """Run trust-store commands through asyncio subprocesses."""

    async def run(self, command: tuple[str, ...], *, check: bool = True) -> CommandResult:
        """Run a command without shell expansion and check its exit status."""
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        communication = asyncio.create_task(process.communicate())
        try:
            standard_output, standard_error = await asyncio.shield(communication)
        except asyncio.CancelledError:
            await communication
            raise
        result = CommandResult(
            returncode=process.returncode or 0,
            standard_output=standard_output,
            standard_error=standard_error,
        )
        if result.returncode and check:
            detail = standard_error.decode("utf-8", errors="replace").strip()
            msg = f"Trust-store command failed: {command[0]}"
            if detail:
                msg = f"{msg}: {detail}"
            raise TrustStoreError(msg)
        return result


async def select_system_trust_store(
    override: TrustStoreOverride = "auto",
    *,
    system_name: str | None = None,
    os_release: Mapping[str, str] | None = None,
) -> SystemTrustStore:
    """Return the requested or automatically detected trust-store integration."""
    if override == "macos":
        from auth_guide.platform_trust.macos import MacOSSystemTrustStore

        return MacOSSystemTrustStore()
    if override == "debian":
        from auth_guide.platform_trust.debian import DebianSystemTrustStore

        return DebianSystemTrustStore()
    if override == "redhat":
        from auth_guide.platform_trust.redhat import RedHatSystemTrustStore

        return RedHatSystemTrustStore()

    detected_system = system_name or platform.system()
    if detected_system == "Darwin":
        from auth_guide.platform_trust.macos import MacOSSystemTrustStore

        return MacOSSystemTrustStore()
    if detected_system != "Linux":
        msg = f"No supported system trust store for {detected_system}"
        raise UnsupportedTrustStoreError(msg)

    release = os_release if os_release is not None else await _read_os_release()
    identifiers = {
        _unquote_os_release_value(release.get("ID", "")).lower(),
        *_unquote_os_release_value(release.get("ID_LIKE", "")).lower().split(),
    }
    if identifiers & {"debian", "ubuntu"}:
        from auth_guide.platform_trust.debian import DebianSystemTrustStore

        return DebianSystemTrustStore()
    if identifiers & {"rhel", "fedora", "centos", "amzn", "amazon"}:
        from auth_guide.platform_trust.redhat import RedHatSystemTrustStore

        return RedHatSystemTrustStore()
    msg = "No supported Linux trust store was identified"
    raise UnsupportedTrustStoreError(msg)


async def _read_os_release() -> Mapping[str, str]:
    release_text: str | None = None
    for release_path in (Path("/etc/os-release"), Path("/usr/lib/os-release")):
        try:
            release_text = await release_path.read_text(encoding="utf-8")
        except OSError:
            continue
        break
    if release_text is None:
        raise UnsupportedTrustStoreError("Linux distribution metadata is unavailable")

    fields: dict[str, str] = {}
    for line in release_text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", maxsplit=1)
        fields[key] = _unquote_os_release_value(value)
    return fields


def _unquote_os_release_value(value: str) -> str:
    """Return an os-release value without matching surrounding quotes."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
