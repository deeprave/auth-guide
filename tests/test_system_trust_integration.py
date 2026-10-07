"""Opt-in integration test for supported system TLS trust."""

import asyncio
import os
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from platform import system

import pytest
from anyio import Path as AsyncPath

from auth_guide.secrets import PlatformSecretProvider
from auth_guide.system_trust import select_system_trust_store
from auth_guide.tls import LocalCertificateAuthority


@dataclass
class MemoryKeyring:
    """A minimal keyring double for an isolated certificate-authority test."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        del self.values[(service_name, username)]


async def connect_with_native_system_trust(authority: LocalCertificateAuthority, directory: AsyncPath) -> None:
    """Connect to an issued leaf with the host's native system trust client."""
    material = await authority.get_active_server_tls_material()
    await directory.mkdir()
    certificate_path = directory / "server-certificate.pem"
    private_key_path = directory / "server-private-key.pem"
    await certificate_path.write_text(material.certificate_pem, encoding="ascii")
    await private_key_path.write_text(material.private_key_pem, encoding="ascii")
    await private_key_path.chmod(0o600)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(certificate_path), str(private_key_path))

    async def handle_connection(_: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ntrusted")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_connection, "127.0.0.1", 0, ssl=server_context)
    try:
        port = server.sockets[0].getsockname()[1]
        if system() == "Darwin":
            process = await asyncio.create_subprocess_exec(
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--connect-timeout",
                "5",
                "--max-time",
                "10",
                f"https://localhost:{port}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                standard_output, standard_error = await asyncio.wait_for(process.communicate(), timeout=11)
            except TimeoutError as error:
                process.kill()
                await process.wait()
                msg = "native macOS TLS client did not complete within the test timeout"
                raise AssertionError(msg) from error
            assert process.returncode == 0, standard_error.decode("utf-8", errors="replace")
            assert standard_output == b"trusted"
        else:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                port,
                ssl=ssl.create_default_context(),
                server_hostname="localhost",
            )
            try:
                assert (await reader.read()).endswith(b"trusted")
            finally:
                writer.close()
                await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.skipif(
    system() not in {"Darwin", "Linux"} or os.environ.get("AUTH_GUIDE_SYSTEM_TRUST_TESTS") != "1",
    reason="requires an opt-in supported system trust-store modification",
)
@pytest.mark.anyio
async def test_system_trust_accepts_an_issued_localhost_leaf(tmp_path: Path) -> None:
    trust_store = await select_system_trust_store()
    if trust_store.name not in {"macos", "debian"}:
        pytest.skip("requires macOS or a Debian-family system trust store")

    async with PlatformSecretProvider("auth-guide-system-trust", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path / "authority", secrets) as authority:
            await authority.initialise()
            await authority.install_system_trust(trust_store)
            try:
                await connect_with_native_system_trust(authority, AsyncPath(tmp_path / "server"))
            finally:
                await authority.remove_system_trust(trust_store)


@pytest.mark.anyio
@pytest.mark.skipif(system() != "Darwin", reason="requires the macOS Security framework")
async def test_macos_security_framework_accepts_issued_localhost_leaf_without_keychain_mutation(
    tmp_path: Path,
) -> None:
    async with PlatformSecretProvider("auth-guide-macos-security-framework", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path / "authority", secrets) as authority:
            await authority.initialise()
            material = await authority.get_active_server_tls_material()
            leaf_path = AsyncPath(tmp_path / "leaf.pem")
            root_path = AsyncPath(tmp_path / "root.pem")
            await leaf_path.write_text(material.certificate_pem, encoding="ascii")
            await root_path.write_text(await authority.get_root_certificate(), encoding="ascii")

            process = await asyncio.create_subprocess_exec(
                "/usr/bin/security",
                "verify-cert",
                "-q",
                "-N",
                "-L",
                "-p",
                "ssl",
                "-n",
                "localhost",
                "-c",
                str(leaf_path),
                "-r",
                str(root_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, standard_error = await asyncio.wait_for(process.communicate(), timeout=10)
            except TimeoutError as error:
                process.kill()
                await process.wait()
                msg = "macOS Security framework evaluation did not complete within the test timeout"
                raise AssertionError(msg) from error
            assert process.returncode == 0, standard_error.decode("utf-8", errors="replace")
