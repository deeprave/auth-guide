"""Red Hat-family p11-kit trust integration."""

from dataclasses import dataclass, field

from auth_guide.platform_trust.common import (
    CommandRunner,
    install_linux_certificate,
    linux_anchor_path,
    uninstall_linux_certificate,
)
from auth_guide.system_trust import SubprocessCommandRunner


@dataclass(frozen=True, slots=True)
class RedHatSystemTrustStore:
    """Red Hat-family p11-kit trust-store implementation."""

    runner: CommandRunner = field(default_factory=SubprocessCommandRunner)
    name: str = field(default="redhat", init=False)

    async def install_certificate(self, certificate_pem: str) -> None:
        """Install a p11-kit anchor then regenerate compatibility stores."""
        await install_linux_certificate(
            certificate_pem,
            linux_anchor_path("/etc/pki/ca-trust/source/anchors", certificate_pem),
            ("sudo", "update-ca-trust"),
            self.runner,
        )

    async def verify_certificate_absent(self, certificate_pem: str, *, certificate_fingerprint: str) -> None:
        """Require the certificate-specific anchor to be absent before install."""
        del certificate_fingerprint
        await self.runner.run(
            (
                "sudo",
                "test",
                "!",
                "-e",
                linux_anchor_path("/etc/pki/ca-trust/source/anchors", certificate_pem),
            )
        )

    async def uninstall_certificate(self, certificate_pem: str, *, certificate_fingerprint: str | None = None) -> None:
        """Remove the provider anchor then regenerate compatibility stores."""
        del certificate_fingerprint
        await uninstall_linux_certificate(
            linux_anchor_path("/etc/pki/ca-trust/source/anchors", certificate_pem),
            ("sudo", "update-ca-trust"),
            self.runner,
        )
