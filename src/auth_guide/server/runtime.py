"""Asynchronous HTTPS provider runtime owned by the server package."""

from __future__ import annotations

import asyncio
import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlsplit

from uvicorn import Server

from auth_guide.accounts import AccountStore, AccountStoreError
from auth_guide.management_api import create_management_application, create_management_server
from auth_guide.secrets import PlatformSecretProvider, SecretProviderError
from auth_guide.server.lifecycle import begin_runtime, end_runtime, mark_ready, paths_for
from auth_guide.tls import CertificateAuthorityNotInitialisedError, LocalCertificateAuthority


class ServerRuntimeError(RuntimeError):
    """A safe, displayable provider-runtime lifecycle failure."""


class RuntimeConfiguration(Protocol):
    """The resolved configuration fields required by the server runtime."""

    @property
    def configuration_file(self) -> Path:
        """Return the selected configuration document."""

    @property
    def listen(self) -> str:
        """Return the effective HTTPS listener address."""


@dataclass(frozen=True, slots=True)
class ServerSettings:
    """The configured runtime inputs retained across one server lifetime."""

    configuration: RuntimeConfiguration
    listen_override: str | None = None
    log_level_console_override: str | None = None
    log_level_override: str | None = None
    log_file_override: str | None = None
    log_syslog_override: bool | None = None
    cli_log_override: bool | None = None

    @property
    def config_dir(self) -> Path:
        """Return the directory that owns provider and lifecycle state."""
        return self.configuration.configuration_file.parent


class ProviderServerRuntime:
    """Own one provider HTTPS runtime and its lifecycle files."""

    def __init__(self, settings: ServerSettings) -> None:
        self._settings = settings
        self._paths = paths_for(settings.config_dir)
        self._generation = 0
        self._shutdown_requested = asyncio.Event()
        self._reload_requested = asyncio.Event()
        self._reload_after_ready = False

    async def serve(self, on_ready: Callable[[], Awaitable[None]] | None = None) -> None:
        """Serve HTTPS until SIGTERM/SIGINT, including SIGHUP rebuilds."""
        self._install_signal_handlers()
        claimed = False
        try:
            await begin_runtime(self._paths, self._settings.configuration.listen)
            claimed = True
            while not self._shutdown_requested.is_set():
                try:
                    await self._serve_generation(on_ready if self._generation == 0 else None)
                except ServerRuntimeError:
                    if self._generation == 0:
                        raise
                    from auth_guide.cli.logging import get_logger

                    get_logger("auth_guide").exception("Server rebuild failed")
                    raise
                if self._shutdown_requested.is_set():
                    return
                if not self._reload_requested.is_set() and not self._reload_after_ready:
                    return
                self._reload_requested = asyncio.Event()
                self._reload_after_ready = False
                self._reload_configuration()
        finally:
            self._remove_signal_handlers()
            if claimed:
                await end_runtime(self._paths)

    async def _serve_generation(self, on_ready: Callable[[], Awaitable[None]] | None) -> None:
        """Build and serve one generation until it is stopped or restarted."""
        from auth_guide.cli.config import CLIConfiguration
        from auth_guide.cli.logging import configure_logging

        configuration = self._settings.configuration
        host, port = _listen_host_port(configuration.listen)
        configure_logging(cast(CLIConfiguration, configuration), cli_only=False)
        try:
            async with PlatformSecretProvider("auth-guide") as secrets:
                async with LocalCertificateAuthority(self._settings.config_dir, secrets) as authority:
                    store = AccountStore(self._settings.config_dir, secrets)
                    try:
                        await store.start()
                        if await store.migration_required():
                            raise ServerRuntimeError("Account store migration is required")
                        server = await create_management_server(
                            create_management_application(store),
                            authority,
                            host=host,
                            port=port,
                            install_signal_handlers=False,
                        )
                        serving = asyncio.create_task(server.serve())
                        while not server.started:
                            if serving.done():
                                await serving
                                raise ServerRuntimeError("HTTPS server stopped before becoming ready")
                            await asyncio.sleep(0.01)
                        self._generation += 1
                        await mark_ready(self._paths, configuration.listen, self._generation)
                        if on_ready is not None:
                            await on_ready()
                        if self._reload_after_ready:
                            server.should_exit = True
                        await self._wait_for_server_exit(server, serving)
                    finally:
                        await store.aclose()
        except (
            AccountStoreError,
            CertificateAuthorityNotInitialisedError,
            SecretProviderError,
            OSError,
            ValueError,
        ) as error:
            raise ServerRuntimeError(str(error)) from error

    async def _wait_for_server_exit(self, server: Server, serving: asyncio.Task[None]) -> None:
        """Request Uvicorn shutdown once a lifecycle signal arrives."""
        while not serving.done():
            if self._shutdown_requested.is_set() or self._reload_requested.is_set():
                server.should_exit = True
            await asyncio.sleep(0.02)
        await serving

    def _install_signal_handlers(self) -> None:
        """Route Unix lifecycle signals into this running event loop."""
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, self._shutdown_requested.set)
        loop.add_signal_handler(signal.SIGINT, self._shutdown_requested.set)
        loop.add_signal_handler(signal.SIGHUP, self._handle_reload_signal)

    def _remove_signal_handlers(self) -> None:
        """Remove process signal handlers installed for this runtime."""
        loop = asyncio.get_running_loop()
        for value in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            loop.remove_signal_handler(value)

    def _handle_reload_signal(self) -> None:
        """Queue a HUP received before readiness or request a live rebuild."""
        if self._generation == 0:
            self._reload_after_ready = True
            return
        self._reload_requested.set()

    def _reload_configuration(self) -> None:
        """Re-read TOML while retaining this process's CLI listen override."""
        from auth_guide.cli.config import resolve_configuration

        current = self._settings.configuration
        refreshed = resolve_configuration(
            current.configuration_file,
            listen=self._settings.listen_override,
            log_level_console=self._settings.log_level_console_override,
            log_level=self._settings.log_level_override,
            log_file=self._settings.log_file_override,
            log_syslog=self._settings.log_syslog_override,
            cli_log=self._settings.cli_log_override,
        )
        self._settings = ServerSettings(
            refreshed,
            self._settings.listen_override,
            self._settings.log_level_console_override,
            self._settings.log_level_override,
            self._settings.log_file_override,
            self._settings.log_syslog_override,
            self._settings.cli_log_override,
        )


def _listen_host_port(listen: str) -> tuple[str, int]:
    """Parse the supported HTTPS listener form into Uvicorn bind arguments."""
    parsed = urlsplit(listen)
    if parsed.scheme != "https" or parsed.hostname is None or parsed.path not in {"", "/"}:
        raise ServerRuntimeError("Provider listen address must be an HTTPS host and port")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ServerRuntimeError("Provider listen address must be an HTTPS host and port")
    return parsed.hostname, parsed.port or 443
