"""Behaviour tests for privileged platform trust-store operations."""

import asyncio
from dataclasses import dataclass, field

import pytest
from anyio import Path

from auth_guide.platform_trust.common import CommandResult, CommandRunner
from auth_guide.platform_trust.debian import DebianSystemTrustStore
from auth_guide.platform_trust.macos import MacOSSystemTrustStore
from auth_guide.platform_trust.redhat import RedHatSystemTrustStore
from auth_guide.secrets import PlatformSecretProvider
from auth_guide.system_trust import SubprocessCommandRunner
from auth_guide.tls import LocalCertificateAuthority

ROOT_CERTIFICATE = "-----BEGIN CERTIFICATE-----\npublic-root\n-----END CERTIFICATE-----\n"


@dataclass
class RecordingCommandRunner(CommandRunner):
    """Records platform commands and the temporary public certificate content."""

    commands: list[tuple[str, ...]] = field(default_factory=list)
    temporary_certificate: Path | None = None
    temporary_certificate_contents: str | None = None
    missing_macos_items: bool = False

    async def run(self, command: tuple[str, ...], *, check: bool = True) -> CommandResult:
        del check
        self.commands.append(command)
        if command[:4] == ("sudo", "install", "-m", "0644"):
            self.temporary_certificate = Path(command[4])
            self.temporary_certificate_contents = await self.temporary_certificate.read_text(encoding="ascii")
        if command[:3] in {
            ("sudo", "security", "add-trusted-cert"),
            ("security", "add-trusted-cert", "-r"),
        }:
            self.temporary_certificate = Path(command[-1])
            self.temporary_certificate_contents = await self.temporary_certificate.read_text(encoding="ascii")
        if self.missing_macos_items and command[:3] in {
            ("sudo", "security", "remove-trusted-cert"),
            ("sudo", "security", "delete-certificate"),
        }:
            return CommandResult(returncode=1, standard_output=b"", standard_error=b"item not found (-25300)")
        return CommandResult(returncode=0, standard_output=b"", standard_error=b"")


@dataclass
class BlockingRefreshRunner(RecordingCommandRunner):
    """Blocks the refresh command so cancellation occurs between paired steps."""

    refresh_started: asyncio.Event = field(default_factory=asyncio.Event)
    release_refresh: asyncio.Event = field(default_factory=asyncio.Event)

    async def run(self, command: tuple[str, ...], *, check: bool = True) -> CommandResult:
        result = await super().run(command, check=check)
        if command in {("sudo", "update-ca-certificates"), ("sudo", "update-ca-trust")}:
            self.refresh_started.set()
            await self.release_refresh.wait()
        return result


@dataclass
class BlockingProcess:
    """Subprocess double that completes only after cancellation is requested."""

    started: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    completed: bool = False
    returncode: int = 0

    async def communicate(self) -> tuple[bytes, bytes]:
        self.started.set()
        await self.release.wait()
        self.completed = True
        return b"", b""


@dataclass
class MemoryKeyring:
    """Keyring double used only to obtain a valid public root certificate."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        del self.values[(service_name, username)]


@pytest.mark.parametrize(
    ("trust_store", "destination_directory", "refresh_command"),
    [
        (
            DebianSystemTrustStore,
            "/usr/local/share/ca-certificates",
            ("sudo", "update-ca-certificates"),
        ),
        (
            RedHatSystemTrustStore,
            "/etc/pki/ca-trust/source/anchors",
            ("sudo", "update-ca-trust"),
        ),
    ],
)
@pytest.mark.anyio
async def test_linux_trust_store_install_and_uninstall_are_limited_to_privileged_system_steps(
    trust_store: type[DebianSystemTrustStore] | type[RedHatSystemTrustStore],
    destination_directory: str,
    refresh_command: tuple[str, ...],
) -> None:
    runner = RecordingCommandRunner()
    store = trust_store(runner)
    await store.install_certificate(ROOT_CERTIFICATE)
    await store.uninstall_certificate(ROOT_CERTIFICATE)

    assert runner.temporary_certificate_contents == ROOT_CERTIFICATE
    assert runner.temporary_certificate is not None
    assert not await runner.temporary_certificate.exists()
    install_command, install_refresh, remove_command, remove_refresh = runner.commands
    assert install_command[:4] == ("sudo", "install", "-m", "0644")
    assert install_command[4] == str(runner.temporary_certificate)
    assert install_command[5].startswith(f"{destination_directory}/auth-guide-local-ca-")
    assert install_command[5].endswith(".crt")
    assert install_refresh == refresh_command
    assert remove_command == ("sudo", "rm", "-f", install_command[5])
    assert remove_refresh == refresh_command


@pytest.mark.anyio
async def test_linux_trust_refresh_completes_after_cancellation_of_a_started_install() -> None:
    runner = BlockingRefreshRunner()
    store = DebianSystemTrustStore(runner)
    installing = asyncio.create_task(store.install_certificate(ROOT_CERTIFICATE))
    await runner.refresh_started.wait()
    installing.cancel()
    runner.release_refresh.set()

    with pytest.raises(asyncio.CancelledError):
        await installing

    assert runner.commands[-1] == ("sudo", "update-ca-certificates")


@pytest.mark.anyio
async def test_macos_install_uses_only_the_system_keychain_privileged_operation() -> None:
    runner = RecordingCommandRunner()
    await MacOSSystemTrustStore(runner).install_certificate(ROOT_CERTIFICATE)

    assert runner.temporary_certificate_contents is not None
    assert runner.temporary_certificate_contents.startswith("-----BEGIN CERTIFICATE-----")
    assert runner.temporary_certificate is not None
    assert not await runner.temporary_certificate.exists()
    command = runner.commands[0]
    assert command[:3] == ("sudo", "security", "add-trusted-cert")
    assert command[command.index("-p") + 1] == "ssl"
    assert command[command.index("-k") + 1] == "/Library/Keychains/System.keychain"
    assert command[-1] == str(runner.temporary_certificate)


@pytest.mark.anyio
async def test_macos_uninstall_removes_admin_trust_before_the_system_keychain_item(tmp_path: Path) -> None:
    runner = RecordingCommandRunner()
    async with PlatformSecretProvider("auth-guide-macos-uninstall", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            await authority.remove_system_trust(MacOSSystemTrustStore(runner))

    remove_trust, remove_certificate = runner.commands
    assert remove_trust[:4] == ("sudo", "security", "remove-trusted-cert", "-d")
    assert remove_certificate[:3] == ("sudo", "security", "delete-certificate")
    assert remove_certificate[-1] == "/Library/Keychains/System.keychain"


@pytest.mark.anyio
async def test_macos_uninstall_treats_absent_trust_artifacts_as_already_removed(tmp_path: Path) -> None:
    runner = RecordingCommandRunner(missing_macos_items=True)
    async with PlatformSecretProvider("auth-guide-macos-idempotent", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            await authority.remove_system_trust(MacOSSystemTrustStore(runner))

    assert any(command[:3] == ("sudo", "security", "delete-certificate") for command in runner.commands)


@pytest.mark.anyio
async def test_subprocess_runner_completes_a_started_command_before_propagating_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = BlockingProcess()

    async def create_process(*_: object, **__: object) -> BlockingProcess:
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    command = ("command",)
    running = asyncio.create_task(SubprocessCommandRunner().run(command))
    await process.started.wait()
    running.cancel()
    process.release.set()

    with pytest.raises(asyncio.CancelledError):
        await running

    assert process.completed
