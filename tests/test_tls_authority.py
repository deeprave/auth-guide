"""Behaviour tests for the provider-owned local certificate authority."""

import asyncio
import json
import ssl
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from anyio import Path as AsyncPath
from cryptography import x509

from auth_guide.secrets import PlatformSecretProvider
from auth_guide.system_trust import SystemTrustStore
from auth_guide.tls import (
    CertificateAuthorityAlreadyInitialisedError,
    CertificateAuthorityNotInitialisedError,
    CertificateAuthorityRotationError,
    CertificateMetadata,
    LocalCertificateAuthority,
)


@dataclass
class MemoryKeyring:
    """A keyring double that exercises the public secret-provider boundary."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        del self.values[(service_name, username)]


@dataclass
class FailingSecondDeleteKeyring(MemoryKeyring):
    """Fails one cleanup delete after an earlier cleanup delete succeeds."""

    delete_calls: int = 0
    failed: bool = False

    def delete_password(self, service_name: str, username: str) -> None:
        self.delete_calls += 1
        if self.delete_calls == 2 and not self.failed:
            self.failed = True
            raise RuntimeError("temporary keyring failure")
        super().delete_password(service_name, username)


@dataclass
class RecordingTrustStore(SystemTrustStore):
    """Captures the public root passed through the trust-store boundary."""

    name: str = "recording"
    checked_certificates: list[str] = field(default_factory=list)
    installed_certificates: list[str] = field(default_factory=list)
    removed_certificates: list[str] = field(default_factory=list)

    async def install_certificate(self, certificate_pem: str) -> None:
        self.installed_certificates.append(certificate_pem)

    async def verify_certificate_absent(self, certificate_pem: str, *, certificate_fingerprint: str) -> None:
        del certificate_fingerprint
        self.checked_certificates.append(certificate_pem)

    async def uninstall_certificate(self, certificate_pem: str, *, certificate_fingerprint: str | None = None) -> None:
        del certificate_fingerprint
        self.removed_certificates.append(certificate_pem)


@dataclass
class RetryableRemovalTrustStore(RecordingTrustStore):
    """Fails its first root removal to exercise the authority retry boundary."""

    removal_failed: bool = False

    async def uninstall_certificate(self, certificate_pem: str, *, certificate_fingerprint: str | None = None) -> None:
        if not self.removal_failed:
            self.removal_failed = True
            raise RuntimeError("system trust store unavailable")
        await super().uninstall_certificate(certificate_pem, certificate_fingerprint=certificate_fingerprint)


async def probe_active_leaf(
    authority: LocalCertificateAuthority, directory: AsyncPath, trusted_root: str | None = None
) -> int:
    """Connect through TLS using the authority root and return the leaf serial."""
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
        writer.write(b"ok")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_connection, "127.0.0.1", 0, ssl=server_context)
    try:
        port = server.sockets[0].getsockname()[1]
        client_context = ssl.create_default_context(cadata=trusted_root or await authority.get_root_certificate())
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=client_context,
            server_hostname="localhost",
        )
        try:
            assert await reader.read() == b"ok"
            ssl_object = writer.get_extra_info("ssl_object")
            assert isinstance(ssl_object, ssl.SSLObject)
            certificate = x509.load_der_x509_certificate(ssl_object.getpeercert(binary_form=True))
            return certificate.serial_number
        finally:
            writer.close()
            await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.anyio
async def test_initialise_creates_a_localhost_certificate_once(tmp_path: Path) -> None:
    keyring = MemoryKeyring()
    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            certificate = await authority.initialise()
            with pytest.raises(CertificateAuthorityAlreadyInitialisedError):
                await authority.initialise()

    assert certificate.identities == ("localhost", "127.0.0.1", "::1")
    assert certificate.serial_number
    assert certificate.not_valid_after > certificate.not_valid_before
    assert len(keyring.values) == 2


@pytest.mark.anyio
async def test_concurrent_authorities_share_one_initialisation_outcome(tmp_path: Path) -> None:
    keyring = MemoryKeyring()
    async with PlatformSecretProvider("auth-guide-concurrent-initialise", keyring) as secrets:
        async with (
            LocalCertificateAuthority(tmp_path, secrets) as first,
            LocalCertificateAuthority(tmp_path, secrets) as second,
        ):
            first_result, second_result = await asyncio.gather(
                first.initialise(), second.initialise(), return_exceptions=True
            )

    outcomes = (first_result, second_result)
    assert sum(isinstance(outcome, CertificateMetadata) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, CertificateAuthorityAlreadyInitialisedError) for outcome in outcomes) == 1
    assert len(keyring.values) == 2


@pytest.mark.anyio
async def test_lifecycle_operations_require_initialisation(tmp_path: Path) -> None:
    async with PlatformSecretProvider("auth-guide", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            with pytest.raises(CertificateAuthorityNotInitialisedError):
                await authority.rotate_server_certificate(("example.test",))
            with pytest.raises(CertificateAuthorityNotInitialisedError):
                await authority.get_active_server_tls_material()


@pytest.mark.anyio
async def test_system_trust_operations_receive_only_the_public_root(tmp_path: Path) -> None:
    trust_store = RecordingTrustStore()
    async with PlatformSecretProvider("auth-guide", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            with pytest.raises(CertificateAuthorityNotInitialisedError):
                await authority.install_system_trust(trust_store)
            await authority.initialise()
            await authority.install_system_trust(trust_store)
            await authority.remove_system_trust(trust_store)

    assert trust_store.removed_certificates == trust_store.installed_certificates
    assert trust_store.checked_certificates == trust_store.installed_certificates
    assert "BEGIN CERTIFICATE" in trust_store.installed_certificates[0]
    assert "PRIVATE KEY" not in trust_store.installed_certificates[0]


@pytest.mark.anyio
async def test_active_server_tls_material_is_available_after_initialisation(tmp_path: Path) -> None:
    async with PlatformSecretProvider("auth-guide", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            material = await authority.get_active_server_tls_material()

    assert "BEGIN CERTIFICATE" in material.certificate_pem
    assert "BEGIN PRIVATE KEY" in material.private_key_pem
    assert "PRIVATE KEY" not in repr(material)


@pytest.mark.anyio
async def test_issued_ecdsa_leaf_declares_tls_signature_usage(tmp_path: Path) -> None:
    async with PlatformSecretProvider("auth-guide-leaf-usage", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            material = await authority.get_active_server_tls_material()

    certificate = x509.load_pem_x509_certificate(material.certificate_pem.encode("ascii"))
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature


@pytest.mark.anyio
@pytest.mark.parametrize("identities", [("*.example.test",), ("localhost", "LOCALHOST")])
async def test_invalid_or_duplicate_identities_are_rejected(tmp_path: Path, identities: tuple[str, ...]) -> None:
    async with PlatformSecretProvider("auth-guide-identity-validation", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            with pytest.raises(ValueError, match="identity"):
                await authority.initialise(identities)


@pytest.mark.anyio
async def test_valid_internationalised_identity_is_issued_in_certificate_form(tmp_path: Path) -> None:
    async with PlatformSecretProvider("auth-guide-idna", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            certificate = await authority.initialise(("bücher.example",))

    assert certificate.identities == ("xn--bcher-kva.example",)


@pytest.mark.anyio
async def test_malformed_persisted_metadata_is_reported_as_a_validation_error(tmp_path: Path) -> None:
    metadata_path = AsyncPath(tmp_path) / "certificates.json"
    await metadata_path.write_text("not-json", encoding="utf-8")
    async with PlatformSecretProvider("auth-guide-malformed-metadata", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            with pytest.raises(ValueError, match="Certificate metadata is invalid"):
                await authority.get_certificate_lifecycle()


@pytest.mark.anyio
async def test_ca_rotation_rejects_malformed_pending_removal_metadata(tmp_path: Path) -> None:
    """A corrupt pending-removal record cannot be overwritten by a new authority."""
    trust_store = RecordingTrustStore()
    metadata_path = AsyncPath(tmp_path) / "certificates.json"
    async with PlatformSecretProvider("auth-guide-malformed-pending-removal", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            document = json.loads(await metadata_path.read_text(encoding="utf-8"))
            document["pending_authority_removal"] = "invalid"
            await metadata_path.write_text(json.dumps(document), encoding="utf-8")

            with pytest.raises(ValueError, match="pending authority removal"):
                await authority.rotate_certificate_authority(trust_store)

    assert trust_store.installed_certificates == []


@pytest.mark.anyio
async def test_new_https_connections_use_the_active_rotated_leaf(tmp_path: Path) -> None:
    async with PlatformSecretProvider("auth-guide", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path / "authority", secrets) as authority:
            original = await authority.initialise()
            original_serial = await probe_active_leaf(authority, AsyncPath(tmp_path / "first"))
            replacement = await authority.rotate_server_certificate(("localhost", "127.0.0.1", "::1"))
            replacement_serial = await probe_active_leaf(authority, AsyncPath(tmp_path / "second"))

    assert original_serial == int(original.serial_number)
    assert replacement_serial == int(replacement.serial_number)
    assert replacement_serial != original_serial


@pytest.mark.anyio
async def test_certificate_lifecycle_audit_reports_active_and_retired_records(tmp_path: Path) -> None:
    async with PlatformSecretProvider("auth-guide", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            await authority.rotate_server_certificate(("localhost", "127.0.0.1", "::1"))
            lifecycle = await authority.get_certificate_lifecycle()

    assert lifecycle.active.state == "active"
    assert lifecycle.retired[0].state == "retired"


@pytest.mark.anyio
async def test_emergency_ca_rotation_replaces_the_trusted_root_and_active_leaf(tmp_path: Path) -> None:
    keyring = MemoryKeyring()
    trust_store = RecordingTrustStore()
    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            original = await authority.initialise()
            await authority.install_system_trust(trust_store)
            replacement = await authority.rotate_certificate_authority(trust_store)
            assert await probe_active_leaf(authority, AsyncPath(tmp_path / "replacement")) == int(
                replacement.serial_number
            )

    assert replacement.serial_number != original.serial_number
    assert len(keyring.values) == 2
    assert trust_store.removed_certificates == [trust_store.installed_certificates[0]]


@pytest.mark.anyio
async def test_emergency_ca_rotation_retries_only_failed_old_root_removal(tmp_path: Path) -> None:
    keyring = MemoryKeyring()
    trust_store = RetryableRemovalTrustStore()
    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            await authority.install_system_trust(trust_store)
            with pytest.raises(CertificateAuthorityRotationError):
                await authority.rotate_certificate_authority(trust_store)
            active_after_failure = await authority.get_certificate_lifecycle()
            replacement = await authority.rotate_certificate_authority(trust_store)

    assert replacement == active_after_failure.active
    assert len(keyring.values) == 2
    assert trust_store.removed_certificates == [trust_store.installed_certificates[0]]


@pytest.mark.anyio
async def test_removing_system_trust_completes_pending_old_root_removal(tmp_path: Path) -> None:
    """Removing trust drains an interrupted rotation before removing the active root."""
    trust_store = RetryableRemovalTrustStore()
    async with PlatformSecretProvider("auth-guide", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            await authority.install_system_trust(trust_store)
            with pytest.raises(CertificateAuthorityRotationError):
                await authority.rotate_certificate_authority(trust_store)
            await authority.remove_system_trust(trust_store)

    assert trust_store.removed_certificates == trust_store.installed_certificates


@pytest.mark.anyio
async def test_pending_ca_cleanup_recovers_when_the_old_ca_key_was_already_deleted(tmp_path: Path) -> None:
    keyring = FailingSecondDeleteKeyring()
    trust_store = RecordingTrustStore()
    async with PlatformSecretProvider("auth-guide-partial-cleanup", keyring) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            await authority.initialise()
            await authority.install_system_trust(trust_store)
            with pytest.raises(CertificateAuthorityRotationError):
                await authority.rotate_certificate_authority(trust_store)
            replacement = await authority.rotate_certificate_authority(trust_store)

    assert replacement.serial_number
    assert len(keyring.values) == 2
    assert keyring.failed


@pytest.mark.anyio
async def test_rotating_a_leaf_updates_the_observable_lifecycle(tmp_path: Path) -> None:
    async with PlatformSecretProvider("auth-guide", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(tmp_path, secrets) as authority:
            original = await authority.initialise()
            replacement = await authority.rotate_server_certificate(("example.test",))
            lifecycle = await authority.get_certificate_lifecycle()

    assert replacement.serial_number != original.serial_number
    assert replacement.identities == ("example.test",)
    assert lifecycle.active == replacement
    assert lifecycle.retired == (
        CertificateMetadata(
            identities=("localhost", "127.0.0.1", "::1"),
            serial_number=original.serial_number,
            not_valid_before=original.not_valid_before,
            not_valid_after=original.not_valid_after,
            subject=original.subject,
            state="retired",
        ),
    )
