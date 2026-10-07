"""Provider-owned private local certificate authority."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4
from weakref import WeakValueDictionary

from anyio import Path as AsyncPath
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from auth_guide.certificate_operations import CertificateOperations
from auth_guide.config_paths import get_auth_config_dir
from auth_guide.secrets import MissingSecretError, PlatformSecretProvider, SecretReference
from auth_guide.system_trust import SystemTrustStore

DEFAULT_IDENTITIES = ("localhost", "127.0.0.1", "::1")

_CONFIGURATION_MUTATION_LOCKS: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()
logger = logging.getLogger(__name__)


class CertificateAuthorityAlreadyInitialisedError(RuntimeError):
    """Raised when CA initialisation would replace existing public state."""


class CertificateAuthorityNotInitialisedError(RuntimeError):
    """Raised when a CA lifecycle operation requires missing public state."""


class CertificateAuthorityRotationError(RuntimeError):
    """Raised when an emergency CA rotation needs a recoverable retry."""


class _MetadataPublicationCancelled(asyncio.CancelledError):
    """Signals that a cancelled caller's metadata publication completed."""


@dataclass(frozen=True, slots=True)
class CertificateMetadata:
    """Public lifecycle metadata for an active server certificate."""

    identities: tuple[str, ...]
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    subject: str
    state: Literal["active", "retired"]


@dataclass(frozen=True, slots=True)
class CertificateLifecycle:
    """The active and retired public records for the local CA."""

    active: CertificateMetadata
    retired: tuple[CertificateMetadata, ...]


@dataclass(frozen=True, slots=True)
class ServerTLSMaterial:
    """The active server certificate and in-memory private key for HTTPS setup."""

    certificate_pem: str
    private_key_pem: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _CertificateMaterial:
    ca_private_key: str
    ca_certificate: str
    ca_serial_number: str
    server_private_key: str
    server_certificate: str
    metadata: CertificateMetadata


@dataclass(frozen=True, slots=True)
class _ServerCertificateMaterial:
    private_key: str
    certificate: str
    metadata: CertificateMetadata


class LocalCertificateAuthority:
    """Create the initial local CA and server certificate for the provider."""

    def __init__(
        self,
        config_dir: str | Path | AsyncPath | None = None,
        secrets: PlatformSecretProvider | None = None,
        certificate_operations: CertificateOperations | None = None,
    ) -> None:
        if secrets is None:
            raise TypeError("Local certificate authority requires a platform secret provider")
        self._config_dir = AsyncPath(get_auth_config_dir(None if config_dir is None else str(config_dir)))
        self._secrets = secrets
        self._certificate_operations = certificate_operations or CertificateOperations()
        self._owns_certificate_operations = certificate_operations is None
        configuration_root = str(self._config_dir)
        self._mutation_lock = _CONFIGURATION_MUTATION_LOCKS.setdefault(configuration_root, asyncio.Lock())

    async def __aenter__(self) -> "LocalCertificateAuthority":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def start(self) -> None:
        """Start the authority-owned certificate operations boundary."""
        await self._certificate_operations.start()

    async def aclose(self) -> None:
        """Stop the authority-owned certificate operations boundary."""
        if self._owns_certificate_operations:
            await self._certificate_operations.aclose()

    async def initialise(self, identities: tuple[str, ...] = DEFAULT_IDENTITIES) -> CertificateMetadata:
        """Create an active server certificate for the supplied identities."""
        async with self._mutation_lock:
            metadata_path = self._metadata_path
            active_certificate = await _read_active_certificate(metadata_path)
            if active_certificate is not None:
                msg = "Local certificate authority is already initialised"
                raise CertificateAuthorityAlreadyInitialisedError(msg)

            material = await self._certificate_operations.call(partial(_create_certificate_material, identities))
            ca_key_reference = SecretReference(f"tls-ca-private-key-{material.ca_serial_number}")
            server_key_reference = SecretReference(f"tls-server-private-key-{material.metadata.serial_number}")
            try:
                await self._secrets.store(ca_key_reference, material.ca_private_key)
                await self._secrets.store(server_key_reference, material.server_private_key)
                await _write_metadata(metadata_path, material, ca_key_reference, server_key_reference)
            except _MetadataPublicationCancelled:
                raise
            except BaseException:
                await _delete_secret_references(self._secrets, ca_key_reference, server_key_reference)
                raise
            return material.metadata

    @property
    def _metadata_path(self) -> AsyncPath:
        return self._config_dir / "certificates.json"

    async def rotate_server_certificate(self, identities: tuple[str, ...]) -> CertificateMetadata:
        """Replace the active server certificate while retaining its lifecycle record."""
        async with self._mutation_lock:
            metadata_path = self._metadata_path
            document = await _read_metadata_document(metadata_path)
            if document is None:
                msg = "Local certificate authority is not initialised"
                raise CertificateAuthorityNotInitialisedError(msg)

            ca = _mapping(document, "ca")
            active_certificate = _mapping(document, "active_certificate")
            ca_private_key = await self._secrets.resolve(SecretReference(_string(ca, "private_key_reference")))
            material = await self._certificate_operations.call(
                partial(_create_server_certificate_material, identities, ca_private_key, _string(ca, "certificate_pem"))
            )
            server_key_reference = SecretReference(f"tls-server-private-key-{material.metadata.serial_number}")
            try:
                await self._secrets.store(server_key_reference, material.private_key)
                await _replace_active_certificate(metadata_path, document, material, server_key_reference)
            except _MetadataPublicationCancelled:
                raise
            except BaseException:
                await _delete_secret_references(self._secrets, server_key_reference)
                raise
            await _best_effort_delete_secret(
                self._secrets, SecretReference(_string(active_certificate, "private_key_reference"))
            )
            return material.metadata

    async def rotate_certificate_authority(self, trust_store: SystemTrustStore) -> CertificateMetadata:
        """Replace a compromised CA while preserving a recoverable trust-removal state."""
        async with self._mutation_lock:
            return await self._rotate_certificate_authority(trust_store)

    async def _rotate_certificate_authority(self, trust_store: SystemTrustStore) -> CertificateMetadata:
        """Perform one serial emergency authority rotation."""
        metadata_path = self._metadata_path
        document = await _read_metadata_document(metadata_path)
        if document is None:
            msg = "Local certificate authority is not initialised"
            raise CertificateAuthorityNotInitialisedError(msg)

        pending_removal = document.get("pending_authority_removal")
        if isinstance(pending_removal, dict):
            await self._complete_pending_authority_removal(
                metadata_path, document, cast(dict[str, object], pending_removal), trust_store
            )
            return _metadata_from_record(_mapping(document, "active_certificate"))

        active_certificate = _mapping(document, "active_certificate")
        material = await self._certificate_operations.call(
            partial(_create_certificate_material, _metadata_from_record(active_certificate).identities)
        )
        ca_key_reference = SecretReference(f"tls-ca-private-key-{material.ca_serial_number}")
        server_key_reference = SecretReference(f"tls-server-private-key-{material.metadata.serial_number}")
        try:
            await self._secrets.store(ca_key_reference, material.ca_private_key)
            await self._secrets.store(server_key_reference, material.server_private_key)
            await self._certificate_operations.call(
                partial(_validate_authority_certificate, material.ca_certificate, material.ca_private_key)
            )
            fingerprint = await self._certificate_operations.call(
                partial(_certificate_fingerprint, material.ca_certificate)
            )
            await trust_store.verify_certificate_absent(material.ca_certificate, certificate_fingerprint=fingerprint)
            await trust_store.install_certificate(material.ca_certificate)
            await _replace_certificate_authority(
                metadata_path,
                document,
                material,
                ca_key_reference,
                server_key_reference,
            )
        except _MetadataPublicationCancelled:
            raise
        except BaseException:
            await _remove_replacement_authority(
                trust_store,
                self._certificate_operations,
                material.ca_certificate,
                material.ca_private_key,
            )
            await _delete_secret_references(self._secrets, ca_key_reference, server_key_reference)
            raise

        pending = _mapping(document, "pending_authority_removal")
        try:
            await self._complete_pending_authority_removal(metadata_path, document, pending, trust_store)
        except _MetadataPublicationCancelled:
            raise
        except BaseException as error:
            msg = "Replacement authority is active but old root removal is pending"
            raise CertificateAuthorityRotationError(msg) from error
        return material.metadata

    async def _complete_pending_authority_removal(
        self,
        metadata_path: AsyncPath,
        document: dict[str, object],
        pending: dict[str, object],
        trust_store: SystemTrustStore,
    ) -> None:
        old_ca = _mapping(pending, "ca")
        await self._uninstall_certificate(
            trust_store,
            _string(old_ca, "certificate_pem"),
            SecretReference(_string(old_ca, "private_key_reference")),
        )
        await _delete_secret_if_present(self._secrets, SecretReference(_string(old_ca, "private_key_reference")))
        await _delete_secret_if_present(
            self._secrets, SecretReference(_string(pending, "server_private_key_reference"))
        )
        await _clear_pending_authority_removal(metadata_path, document)

    async def install_system_trust(self, trust_store: SystemTrustStore) -> None:
        """Install the initialised public root through one selected trust store."""
        async with self._mutation_lock:
            certificate_pem, private_key_reference = await self._authority_material_references()
            await self._validate_authority_material(certificate_pem, private_key_reference)
            fingerprint = await self._certificate_operations.call(partial(_certificate_fingerprint, certificate_pem))
            await trust_store.verify_certificate_absent(certificate_pem, certificate_fingerprint=fingerprint)
            await trust_store.install_certificate(certificate_pem)

    async def remove_system_trust(self, trust_store: SystemTrustStore) -> None:
        """Remove the initialised public root through one selected trust store."""
        async with self._mutation_lock:
            document = await _read_metadata_document(self._metadata_path)
            if document is None:
                raise CertificateAuthorityNotInitialisedError("Local certificate authority is not initialised")
            pending_removal = document.get("pending_authority_removal")
            if pending_removal is not None:
                if not isinstance(pending_removal, dict):
                    raise ValueError("Certificate metadata pending authority removal is invalid")
                await self._complete_pending_authority_removal(
                    self._metadata_path, document, cast(dict[str, object], pending_removal), trust_store
                )
            authority = _mapping(document, "ca")
            certificate_pem = _string(authority, "certificate_pem")
            private_key_reference = SecretReference(_string(authority, "private_key_reference"))
            await self._uninstall_certificate(trust_store, certificate_pem, private_key_reference)

    async def _authority_material_references(self) -> tuple[str, SecretReference]:
        """Return the active CA certificate and its secret-provider reference."""
        document = await _read_metadata_document(self._metadata_path)
        if document is None:
            raise CertificateAuthorityNotInitialisedError("Local certificate authority is not initialised")
        authority = _mapping(document, "ca")
        return _string(authority, "certificate_pem"), SecretReference(_string(authority, "private_key_reference"))

    async def _uninstall_certificate(
        self, trust_store: SystemTrustStore, certificate_pem: str, private_key_reference: SecretReference
    ) -> None:
        """Derive platform certificate identifiers through the owned worker."""
        try:
            await self._validate_authority_material(certificate_pem, private_key_reference)
        except MissingSecretError:
            pass
        fingerprint = await self._certificate_operations.call(partial(_certificate_fingerprint, certificate_pem))
        await trust_store.uninstall_certificate(certificate_pem, certificate_fingerprint=fingerprint)

    async def _validate_authority_material(self, certificate_pem: str, private_key_reference: SecretReference) -> None:
        """Confirm the configured public root corresponds to its stored key."""
        private_key_pem = await self._secrets.resolve(private_key_reference)
        await self._certificate_operations.call(
            partial(_validate_authority_certificate, certificate_pem, private_key_pem)
        )

    async def get_root_certificate(self) -> str:
        """Return the initialised public root certificate for trust installation."""
        document = await _read_metadata_document(self._metadata_path)
        if document is None:
            msg = "Local certificate authority is not initialised"
            raise CertificateAuthorityNotInitialisedError(msg)
        return _string(_mapping(document, "ca"), "certificate_pem")

    async def get_active_server_tls_material(self) -> ServerTLSMaterial:
        """Return the current server leaf material for in-process HTTPS configuration."""
        async with self._mutation_lock:
            document = await _read_metadata_document(self._metadata_path)
            if document is None:
                msg = "Local certificate authority is not initialised"
                raise CertificateAuthorityNotInitialisedError(msg)
            active_certificate = _mapping(document, "active_certificate")
            return ServerTLSMaterial(
                certificate_pem=_string(active_certificate, "certificate_pem"),
                private_key_pem=await self._secrets.resolve(
                    SecretReference(_string(active_certificate, "private_key_reference"))
                ),
            )

    async def get_certificate_lifecycle(self) -> CertificateLifecycle:
        """Return the active and retired certificate records for lifecycle audit."""
        document = await _read_metadata_document(self._metadata_path)
        if document is None:
            msg = "Local certificate authority is not initialised"
            raise CertificateAuthorityNotInitialisedError(msg)
        retired_records = document.get("retired_certificates")
        if not isinstance(retired_records, list) or not all(isinstance(record, dict) for record in retired_records):
            msg = "Certificate metadata retired records are invalid"
            raise ValueError(msg)
        return CertificateLifecycle(
            active=_metadata_from_record(_mapping(document, "active_certificate")),
            retired=tuple(_metadata_from_record(cast(dict[str, object], record)) for record in retired_records),
        )


async def _delete_secret_references(secrets: PlatformSecretProvider, *references: SecretReference) -> None:
    """Best-effort cleanup that never obscures the triggering failure."""
    for reference in references:
        try:
            await secrets.delete(reference)
        except BaseException:
            continue


async def _best_effort_delete_secret(secrets: PlatformSecretProvider, reference: SecretReference) -> None:
    """Attempt retired-key hygiene without invalidating a committed rotation."""
    try:
        await secrets.delete(reference)
    except asyncio.CancelledError:
        raise
    except BaseException as error:
        logger.warning("Retired TLS key cleanup failed: %s", type(error).__name__)


async def _delete_secret_if_present(secrets: PlatformSecretProvider, reference: SecretReference) -> None:
    """Delete a recovery secret unless a prior cleanup step already removed it."""
    try:
        await secrets.resolve(reference)
    except MissingSecretError:
        return
    await secrets.delete(reference)


async def _remove_replacement_authority(
    trust_store: SystemTrustStore,
    certificate_operations: CertificateOperations,
    certificate_pem: str,
    private_key_pem: str,
) -> None:
    """Best-effort rollback of a replacement root after publication fails."""
    try:
        await certificate_operations.call(partial(_validate_authority_certificate, certificate_pem, private_key_pem))
        fingerprint = await certificate_operations.call(partial(_certificate_fingerprint, certificate_pem))
        await trust_store.uninstall_certificate(certificate_pem, certificate_fingerprint=fingerprint)
    except BaseException:
        pass


def _create_certificate_material(identities: tuple[str, ...]) -> _CertificateMaterial:
    identities = _normalise_identities(identities)

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Auth Guide Local CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_material = _create_server_certificate_material(
        identities,
        _private_key_pem(ca_key),
        ca_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )
    return _CertificateMaterial(
        ca_private_key=_private_key_pem(ca_key),
        ca_certificate=ca_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        ca_serial_number=str(ca_certificate.serial_number),
        server_private_key=server_material.private_key,
        server_certificate=server_material.certificate,
        metadata=server_material.metadata,
    )


def _create_server_certificate_material(
    identities: tuple[str, ...], ca_private_key_pem: str, ca_certificate_pem: str
) -> _ServerCertificateMaterial:
    identities = _normalise_identities(identities)

    ca_private_key = serialization.load_pem_private_key(ca_private_key_pem.encode("ascii"), password=None)
    if not isinstance(ca_private_key, ec.EllipticCurvePrivateKey):
        msg = "Local certificate authority key must be elliptic-curve"
        raise ValueError(msg)
    ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem.encode("ascii"))
    server_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    server_not_valid_after = now + timedelta(days=365)
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identities[0])]))
        .issuer_name(ca_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(server_not_valid_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([_as_general_name(identity) for identity in identities]), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )
    metadata = CertificateMetadata(
        identities=identities,
        serial_number=str(server_certificate.serial_number),
        not_valid_before=server_certificate.not_valid_before_utc,
        not_valid_after=server_certificate.not_valid_after_utc,
        subject=server_certificate.subject.rfc4514_string(),
        state="active",
    )
    return _ServerCertificateMaterial(
        private_key=_private_key_pem(server_key),
        certificate=server_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        metadata=metadata,
    )


async def _read_active_certificate(path: AsyncPath) -> CertificateMetadata | None:
    document = await _read_metadata_document(path)
    if document is None:
        return None
    return _metadata_from_record(_mapping(document, "active_certificate"))


async def _read_metadata_document(path: AsyncPath) -> dict[str, object] | None:
    if not await path.exists():
        return None

    try:
        document = json.loads(await path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Certificate metadata is invalid") from error
    if not isinstance(document, dict):
        raise ValueError("Certificate metadata is invalid")
    return cast(dict[str, object], document)


def _metadata_from_record(record: dict[str, object]) -> CertificateMetadata:
    identities = record.get("identities")
    if not isinstance(identities, list) or not all(isinstance(identity, str) for identity in identities):
        msg = "Certificate metadata identities are invalid"
        raise ValueError(msg)

    return CertificateMetadata(
        identities=tuple(identities),
        serial_number=_string(record, "serial_number"),
        not_valid_before=datetime.fromisoformat(_string(record, "not_valid_before")),
        not_valid_after=datetime.fromisoformat(_string(record, "not_valid_after")),
        subject=_string(record, "subject"),
        state=_state(record),
    )


def _as_general_name(identity: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(identity))
    except ValueError:
        return x509.DNSName(identity)


def _normalise_identities(identities: tuple[str, ...]) -> tuple[str, ...]:
    """Validate operator-selected identities and return certificate-safe forms."""
    if not identities:
        raise ValueError("At least one certificate identity is required")

    seen: set[str] = set()
    normalised: list[str] = []
    for identity in identities:
        if not identity or identity != identity.strip() or "*" in identity:
            raise ValueError(f"Certificate identity is invalid: {identity!r}")
        try:
            canonical = str(ipaddress.ip_address(identity))
        except ValueError:
            canonical = _validate_dns_identity(identity)
        if canonical in seen:
            raise ValueError(f"Certificate identity is duplicated: {identity}")
        seen.add(canonical)
        normalised.append(canonical)
    return tuple(normalised)


def _validate_dns_identity(identity: str) -> str:
    try:
        ascii_identity = identity.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError(f"Certificate DNS identity is invalid: {identity!r}") from error

    name = ascii_identity.removesuffix(".")
    if not name or len(name) > 253:
        raise ValueError(f"Certificate DNS identity is invalid: {identity!r}")
    for label in name.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError(f"Certificate DNS identity is invalid: {identity!r}")
        if not all(character.isascii() and (character.isalnum() or character == "-") for character in label):
            raise ValueError(f"Certificate DNS identity is invalid: {identity!r}")
    return name.lower()


def _private_key_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _certificate_fingerprint(certificate_pem: str) -> str:
    """Return the macOS keychain identifier for a public certificate."""
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    return certificate.fingerprint(hashes.SHA1()).hex().upper()  # nosec B303


def _validate_authority_certificate(certificate_pem: str, private_key_pem: str) -> None:
    """Require a CA certificate before requesting a privileged trust mutation."""
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    except (TypeError, ValueError, x509.ExtensionNotFound) as error:
        raise ValueError("System trust requires a valid CA certificate") from error
    if not constraints.ca or not key_usage.key_cert_sign:
        raise ValueError("System trust requires a CA certificate with certificate-signing usage")
    certificate_public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_public_key = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public_key != private_public_key:
        raise ValueError("System trust requires the configured CA certificate and key to match")


async def _write_metadata(
    path: AsyncPath,
    material: _CertificateMaterial,
    ca_key_reference: SecretReference,
    server_key_reference: SecretReference,
) -> None:
    metadata: dict[str, object] = {
        "ca": {
            "certificate_pem": material.ca_certificate,
            "private_key_reference": ca_key_reference.name,
        },
        "active_certificate": {
            **asdict(material.metadata),
            "certificate_pem": material.server_certificate,
            "private_key_reference": server_key_reference.name,
            "state": "active",
        },
        "retired_certificates": [],
        "version": 1,
    }
    await _write_metadata_document(path, metadata)


async def _replace_certificate_authority(
    path: AsyncPath,
    document: dict[str, object],
    material: _CertificateMaterial,
    ca_key_reference: SecretReference,
    server_key_reference: SecretReference,
) -> None:
    old_ca = _mapping(document, "ca").copy()
    previous_active = _mapping(document, "active_certificate")
    retired_certificates = document.get("retired_certificates")
    if not isinstance(retired_certificates, list):
        msg = "Certificate metadata retired records are invalid"
        raise ValueError(msg)
    retired_certificates.append({**asdict(_metadata_from_record(previous_active)), "state": "retired"})
    document["pending_authority_removal"] = {
        "ca": old_ca,
        "server_private_key_reference": _string(previous_active, "private_key_reference"),
    }
    document["ca"] = {
        "certificate_pem": material.ca_certificate,
        "private_key_reference": ca_key_reference.name,
    }
    document["active_certificate"] = {
        **asdict(material.metadata),
        "certificate_pem": material.server_certificate,
        "private_key_reference": server_key_reference.name,
    }
    await _write_metadata_document(path, document)


async def _clear_pending_authority_removal(path: AsyncPath, document: dict[str, object]) -> None:
    if document.pop("pending_authority_removal", None) is None:
        raise ValueError("Certificate metadata pending authority removal is invalid")
    await _write_metadata_document(path, document)


async def _replace_active_certificate(
    path: AsyncPath,
    document: dict[str, object],
    material: _ServerCertificateMaterial,
    server_key_reference: SecretReference,
) -> None:
    previous_active = _mapping(document, "active_certificate")
    retired = {
        **asdict(_metadata_from_record(previous_active)),
        "state": "retired",
    }
    retired_certificates = document.get("retired_certificates")
    if not isinstance(retired_certificates, list):
        msg = "Certificate metadata retired records are invalid"
        raise ValueError(msg)
    retired_certificates.append(retired)
    document["active_certificate"] = {
        **asdict(material.metadata),
        "certificate_pem": material.certificate,
        "private_key_reference": server_key_reference.name,
        "state": "active",
    }
    await _write_metadata_document(path, document)


async def _write_metadata_document(path: AsyncPath, document: dict[str, object]) -> None:
    """Publish metadata atomically once a mutation has begun.

    A caller cancellation cannot leave a replacement key published without its
    corresponding metadata, or metadata pointing at a key cleaned up by a
    cancellation handler.  The short publication finishes first.
    """
    publication = asyncio.create_task(_publish_metadata_document(path, document))
    try:
        await asyncio.shield(publication)
    except asyncio.CancelledError as error:
        await asyncio.shield(publication)
        raise _MetadataPublicationCancelled from error


async def _publish_metadata_document(path: AsyncPath, document: dict[str, object]) -> None:
    """Write a complete replacement document then atomically rename it."""
    await path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    await temporary_path.write_text(json.dumps(document, default=_json_default, indent=2) + "\n", encoding="utf-8")
    await temporary_path.replace(path)


def _mapping(document: dict[str, object], key: str) -> dict[str, object]:
    value = document.get(key)
    if isinstance(value, dict):
        return cast(dict[str, object], value)
    msg = f"Certificate metadata {key} is invalid"
    raise ValueError(msg)


def _string(record: dict[str, object], key: str) -> str:
    value = record.get(key)
    if isinstance(value, str):
        return value
    msg = f"Certificate metadata {key} is invalid"
    raise ValueError(msg)


def _state(record: dict[str, object]) -> Literal["active", "retired"]:
    value = _string(record, "state")
    if value in {"active", "retired"}:
        return value
    msg = "Certificate metadata state is invalid"
    raise ValueError(msg)


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serialisable")
