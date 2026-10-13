"""Observable lifecycle-file and foreground-runtime behaviour for the provider."""

import asyncio
import base64
import json
import os
import signal
import socket
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path

import anyio
import httpx
import keyring
import pytest
from anyio import Path as AsyncPath
from file_keyring_backend import FileKeyring

from auth_guide.accounts import (
    DATABASE_FILENAME,
    AccountRecord,
    AccountStore,
    AccountTokenRecord,
    Grant,
    generate_account_token,
)
from auth_guide.bootstrap import initialise_provider
from auth_guide.cli.config import resolve_configuration
from auth_guide.secrets import PlatformSecretProvider, SecretReference
from auth_guide.server import ProviderServerRuntime, ServerRuntimeError, ServerSettings
from auth_guide.server.lifecycle import (
    LifecycleError,
    begin_runtime,
    end_runtime,
    paths_for,
    process_is_live,
    read_state,
)
from auth_guide.tls import LocalCertificateAuthority


@dataclass
class MemoryKeyring:
    """Keep real runtime secrets entirely inside this test process."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_password(self, service_name: str, username: str) -> str | None:
        """Return one test-only secret."""
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        """Store one test-only secret."""
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        """Remove one test-only secret."""
        del self.values[(service_name, username)]


@pytest.mark.anyio
async def test_runtime_claims_pid_before_startup_and_removes_metadata_before_it(tmp_path) -> None:
    """A starting runtime exposes a PID and removes its complete state on exit."""
    paths = paths_for(tmp_path)

    await begin_runtime(paths, "https://localhost:8443")

    state = await read_state(paths)
    assert state.state == "starting"
    assert state.pid == os.getpid()
    assert state.listen == "https://localhost:8443"
    assert await paths.pid.exists()
    assert await paths.metadata.exists()

    await end_runtime(paths)

    assert (await read_state(paths)).state == "stopped"
    assert not await paths.metadata.exists()
    assert not await paths.pid.exists()


@pytest.mark.anyio
async def test_rejected_start_preserves_live_runtime_metadata(tmp_path) -> None:
    """A second start never overwrites metadata owned by a live runtime."""
    paths = paths_for(tmp_path)
    await begin_runtime(paths, "https://localhost:8443")
    original = await paths.metadata.read_text(encoding="utf-8")

    with pytest.raises(LifecycleError, match="already running"):
        await begin_runtime(paths, "https://127.0.0.1:9443")

    assert await paths.metadata.read_text(encoding="utf-8") == original
    await end_runtime(paths)


@pytest.mark.anyio
async def test_start_removes_stale_state_before_claiming_its_own_files(tmp_path) -> None:
    """A stale PID and orphan metadata do not block a later runtime."""
    paths = paths_for(tmp_path)
    await AsyncPath(tmp_path).mkdir(parents=True, exist_ok=True)
    await paths.pid.write_text("999999999\n", encoding="ascii")
    await paths.metadata.write_text('{"generation": 7, "listen": "https://old.example"}', encoding="utf-8")

    await begin_runtime(paths, "https://localhost:8443")

    state = await read_state(paths)
    assert state.state == "starting"
    assert state.pid == os.getpid()
    assert state.listen == "https://localhost:8443"
    await end_runtime(paths)


@pytest.mark.anyio
@pytest.mark.parametrize("shutdown_signal", [signal.SIGINT, signal.SIGTERM])
async def test_foreground_runtime_serves_https_rebuilds_and_cleans_up(tmp_path, monkeypatch, shutdown_signal) -> None:
    """The real runtime serves HTTPS, rebuilds on HUP, and removes owned state on TERM."""
    import auth_guide.secrets as secrets_module

    keyring = MemoryKeyring()
    monkeypatch.setattr(secrets_module, "keyring", keyring)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    config_file = Path(tmp_path) / "config.toml"
    await AsyncPath(config_file).write_text(f'listen = "https://127.0.0.1:{port}"\n', encoding="utf-8")
    monkeypatch.setenv("AG_LISTEN", f"https://127.0.0.1:{port}")
    configuration = resolve_configuration(config_file)

    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
        store = AccountStore(tmp_path, secrets)
        await store.initialise()
        account = AccountRecord(
            email="administrator@example.com",
            email_comparison="administrator@example.com",
            grants=[Grant.GUIDE_ADMIN, Grant.ACCOUNTS_READ, Grant.ACCOUNTS_MANAGE, Grant.TOKENS_MANAGE],
        )
        await store.create_account(account, "a sufficiently long initial password")
        issued = await generate_account_token()
        await AccountTokenRecord.create(
            account=account,
            label="administrator",
            verifier=issued.verifier,
            scopes=[Grant.ACCOUNTS_READ, Grant.ACCOUNTS_MANAGE, Grant.TOKENS_MANAGE],
        )
        await store.aclose()

    runtime = ProviderServerRuntime(ServerSettings(configuration))
    ready = asyncio.Event()

    async def mark_ready() -> None:
        """Record the externally observable first readiness transition."""
        ready.set()

    serving = asyncio.create_task(runtime.serve(mark_ready))
    await asyncio.sleep(0)
    os.kill(os.getpid(), signal.SIGHUP)
    await asyncio.wait_for(ready.wait(), timeout=5)
    paths = paths_for(tmp_path)
    for _ in range(100):
        first = await read_state(paths)
        if first.generation == 2:
            break
        await asyncio.sleep(0.02)
    else:
        pytest.fail("Server did not process a HUP received during startup")
    assert first.state == "running"
    assert first.generation == 2

    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            trusted_context = ssl.create_default_context(cadata=await authority.get_root_certificate())
    async with httpx.AsyncClient(verify=trusted_context) as client:
        response = await client.get(f"https://127.0.0.1:{port}/openapi.json")
    assert response.status_code == 200

    await AsyncPath(config_file).write_text('listen = "https://127.0.0.1:9444"\n', encoding="utf-8")
    os.kill(os.getpid(), signal.SIGHUP)
    for _ in range(100):
        rebuilt = await read_state(paths)
        if rebuilt.generation == 3:
            break
        await asyncio.sleep(0.02)
    else:
        pytest.fail("Server did not publish a rebuilt readiness generation")
    assert rebuilt.pid == first.pid
    assert rebuilt.listen == f"https://127.0.0.1:{port}"

    os.kill(os.getpid(), shutdown_signal)
    await asyncio.wait_for(serving, timeout=5)
    assert (await read_state(paths)).state == "stopped"


@pytest.mark.anyio
async def test_runtime_requires_existing_ca_without_initialising_it(tmp_path, monkeypatch) -> None:
    """Server readiness fails safely when local TLS has not been explicitly initialised."""
    import auth_guide.secrets as secrets_module

    keyring = MemoryKeyring()
    monkeypatch.setattr(secrets_module, "keyring", keyring)
    config_file = Path(tmp_path) / "config.toml"
    await AsyncPath(config_file).write_text('listen = "https://127.0.0.1:9443"\n', encoding="utf-8")
    configuration = resolve_configuration(config_file)

    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        store = AccountStore(tmp_path, secrets)
        await store.initialise()
        await store.aclose()

    runtime = ProviderServerRuntime(ServerSettings(configuration))
    with pytest.raises(ServerRuntimeError, match="certificate authority is not initialised"):
        await runtime.serve()

    assert not await (AsyncPath(tmp_path) / "certificates.json").exists()
    assert (await read_state(paths_for(tmp_path))).state == "stopped"


@pytest.mark.anyio
async def test_runtime_does_not_create_or_migrate_an_absent_account_database(tmp_path, monkeypatch) -> None:
    """A server start reports an uninitialised store without changing its database state."""
    import auth_guide.secrets as secrets_module

    keyring = MemoryKeyring()
    monkeypatch.setattr(secrets_module, "keyring", keyring)
    config_file = Path(tmp_path) / "config.toml"
    await AsyncPath(config_file).write_text('listen = "https://127.0.0.1:9444"\n', encoding="utf-8")
    configuration = resolve_configuration(config_file)
    key = base64.b64encode(b"x" * 32).decode("ascii")

    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        await secrets.create(SecretReference("auth-guide-database-key"), key)
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()

    runtime = ProviderServerRuntime(ServerSettings(configuration))
    with pytest.raises(ServerRuntimeError, match="migration is required"):
        await runtime.serve()

    assert not await (AsyncPath(tmp_path) / DATABASE_FILENAME).exists()
    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        assert await secrets.resolve(SecretReference("auth-guide-database-key")) == key


@pytest.mark.anyio
async def test_background_commands_manage_one_real_detached_runtime(tmp_path, monkeypatch) -> None:
    """Start, status, duplicate start, restart and stop work with isolated child secrets."""
    config_file = Path(tmp_path) / "config.toml"
    keyring_file = Path(tmp_path) / "keyring.json"
    log_file = Path(tmp_path) / "server.log"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    await AsyncPath(config_file).write_text(
        f'listen = "https://127.0.0.1:{port}"\nlog_file = "{log_file}"\n', encoding="utf-8"
    )
    environment = {
        **os.environ,
        "AUTH_GUIDE_TEST_KEYRING": str(keyring_file),
        "PYTHON_KEYRING_BACKEND": "file_keyring_backend.FileKeyring",
        "PYTHONPATH": str(Path.cwd() / "tests"),
    }
    monkeypatch.setenv("AUTH_GUIDE_TEST_KEYRING", str(keyring_file))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "file_keyring_backend.FileKeyring")
    monkeypatch.setenv("PYTHONPATH", str(Path.cwd() / "tests"))
    original_keyring = keyring.get_keyring()
    keyring.set_keyring(FileKeyring())

    async def run_cli(*arguments: str):
        """Run one real CLI process with the disposable test keyring."""
        return await anyio.run_process(
            [sys.executable, "-m", "auth_guide", "--config", str(config_file), *arguments],
            env=environment,
            check=False,
        )

    try:
        initialise_ca = await run_cli("ca", "init")
        assert initialise_ca.returncode == 0, initialise_ca.stderr.decode()
        credentials = await initialise_provider(tmp_path, "administrator@example.com")

        async with PlatformSecretProvider("auth-guide") as secrets:
            async with LocalCertificateAuthority(tmp_path, secrets) as authority:
                trusted_context = ssl.create_default_context(cadata=await authority.get_root_certificate())

        started = await run_cli("server", "start")
        assert started.returncode == 0, started.stderr.decode()
        first_status = await run_cli("server", "status")
        assert first_status.returncode == 0
        first = json.loads(first_status.stdout)
        assert first["state"] == "running"

        async with httpx.AsyncClient(verify=trusted_context) as client:
            response = await client.get(f"https://127.0.0.1:{port}/openapi.json")
        assert response.status_code == 200
        log_contents = await AsyncPath(log_file).read_text(encoding="utf-8")
        assert credentials.token not in log_contents
        assert "administrator@example.com" not in log_contents

        duplicate = await run_cli("server", "start")
        assert duplicate.returncode == 1
        assert b"already running" in duplicate.stderr

        restarted = await run_cli("server", "restart")
        assert restarted.returncode == 0, restarted.stderr.decode()
        second_status = await run_cli("server", "status")
        second = json.loads(second_status.stdout)
        assert second["pid"] == first["pid"]
        assert second["generation"] > first["generation"]

        stopped = await run_cli("server", "stop")
        assert stopped.returncode == 0, stopped.stderr.decode()
        final_status = await run_cli("server", "status")
        assert final_status.returncode == 3
        assert json.loads(final_status.stdout)["state"] == "stopped"

        await AsyncPath(config_file).write_text(
            f'listen = "https://127.0.0.1:{port}"\nlog_file = "{log_file}"\n', encoding="utf-8"
        )
        started_again = await run_cli("server", "start")
        assert started_again.returncode == 0, started_again.stderr.decode()
        await AsyncPath(config_file).write_text('listen = "not-an-https-listener"\n', encoding="utf-8")
        failed_rebuild = await run_cli("server", "restart")
        assert failed_rebuild.returncode == 1
        assert b"restart failed" in failed_rebuild.stderr
        failed_status = await run_cli("server", "status")
        assert failed_status.returncode == 3
        assert json.loads(failed_status.stdout)["state"] == "stopped"
    finally:
        state = await read_state(paths_for(tmp_path))
        if state.state in {"running", "starting"} and state.pid is not None:
            os.kill(state.pid, signal.SIGTERM)
            for _ in range(100):
                if not process_is_live(state.pid):
                    break
                await asyncio.sleep(0.02)
        keyring.set_keyring(original_keyring)
