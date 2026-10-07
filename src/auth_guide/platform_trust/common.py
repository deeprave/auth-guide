"""Shared asynchronous primitives for supported system trust stores."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass
from tempfile import gettempdir
from typing import Protocol, TypeVar
from uuid import uuid4

from anyio import Path

ResultT = TypeVar("ResultT")


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Completed command output for a platform-trust operation."""

    returncode: int
    standard_output: bytes
    standard_error: bytes


class CommandRunner(Protocol):
    """Run one platform command without a shell."""

    async def run(self, command: tuple[str, ...], *, check: bool = True) -> CommandResult:
        """Run a command or raise when it fails."""


def linux_anchor_path(directory: str, certificate_pem: str) -> str:
    """Return the certificate-specific Linux trust-anchor path."""
    fingerprint = hashlib.sha256(certificate_pem.encode("ascii")).hexdigest()
    return str(Path(directory) / f"auth-guide-local-ca-{fingerprint}.crt")


async def install_linux_certificate(
    certificate_pem: str, destination: str, refresh_command: tuple[str, ...], runner: CommandRunner
) -> None:
    """Install one certificate-specific Linux trust anchor and refresh trust."""

    async def install_and_refresh() -> None:
        await with_certificate_file(
            certificate_pem,
            lambda path: runner.run(("sudo", "install", "-m", "0644", str(path), destination)),
        )
        await runner.run(refresh_command)

    await _complete_trust_sequence(install_and_refresh())


async def uninstall_linux_certificate(
    destination: str, refresh_command: tuple[str, ...], runner: CommandRunner
) -> None:
    """Remove one certificate-specific Linux trust anchor and refresh trust."""

    async def remove_and_refresh() -> None:
        await runner.run(("sudo", "rm", "-f", destination))
        await runner.run(refresh_command)

    await _complete_trust_sequence(remove_and_refresh())


async def _complete_trust_sequence(operation: Coroutine[object, object, None]) -> None:
    """Finish a started anchor mutation and its required trust refresh together."""
    sequence = asyncio.create_task(operation)
    try:
        await asyncio.shield(sequence)
    except asyncio.CancelledError:
        await asyncio.shield(sequence)
        raise


async def with_certificate_file(certificate_pem: str, operation: Callable[[Path], Awaitable[ResultT]]) -> ResultT:
    """Make a temporary public certificate available for one async operation."""
    path = Path(gettempdir()) / f"auth-guide-{uuid4().hex}.crt"
    async with await path.open("x", encoding="ascii") as certificate_file:
        await certificate_file.write(certificate_pem)
    try:
        return await operation(path)
    finally:
        await path.unlink(missing_ok=True)
