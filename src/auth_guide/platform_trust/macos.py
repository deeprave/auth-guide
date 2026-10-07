"""macOS System Keychain trust integration."""

from dataclasses import dataclass, field

from auth_guide.platform_trust.common import CommandResult, CommandRunner, with_certificate_file
from auth_guide.system_trust import SubprocessCommandRunner, TrustStoreError


@dataclass(frozen=True, slots=True)
class MacOSSystemTrustStore:
    """The macOS System keychain trust-store implementation."""

    runner: CommandRunner = field(default_factory=SubprocessCommandRunner)
    name: str = field(default="macos", init=False)

    async def install_certificate(self, certificate_pem: str) -> None:
        """Install a root certificate in the System keychain with elevation."""
        await with_certificate_file(
            certificate_pem,
            lambda path: self.runner.run(
                (
                    "sudo",
                    "security",
                    "add-trusted-cert",
                    "-d",
                    "-r",
                    "trustRoot",
                    "-p",
                    "ssl",
                    "-k",
                    "/Library/Keychains/System.keychain",
                    str(path),
                )
            ),
        )

    async def verify_certificate_absent(self, certificate_pem: str, *, certificate_fingerprint: str) -> None:
        """Require the System Keychain to have no matching root before install."""
        del certificate_pem
        result = await self.runner.run(
            (
                "sudo",
                "security",
                "find-certificate",
                "-Z",
                "-a",
                "/Library/Keychains/System.keychain",
            ),
            check=False,
        )
        if result.returncode:
            raise TrustStoreError("Unable to inspect the macOS System Keychain")
        if certificate_fingerprint in result.standard_output.decode("utf-8", errors="replace"):
            raise TrustStoreError("The configured CA root is already installed")

    async def uninstall_certificate(self, certificate_pem: str, *, certificate_fingerprint: str | None = None) -> None:
        """Remove exactly the supplied root certificate from the System keychain."""
        if certificate_fingerprint is None:
            raise ValueError("macOS trust removal requires a certificate fingerprint")
        trust_result = await with_certificate_file(
            certificate_pem,
            lambda path: self.runner.run(("sudo", "security", "remove-trusted-cert", "-d", str(path)), check=False),
        )
        _raise_unless_absent(trust_result, "remove macOS trust settings")
        certificate_result = await self.runner.run(
            (
                "sudo",
                "security",
                "delete-certificate",
                "-Z",
                certificate_fingerprint,
                "/Library/Keychains/System.keychain",
            ),
            check=False,
        )
        _raise_unless_absent(certificate_result, "remove the macOS System Keychain certificate")


def _raise_unless_absent(result: CommandResult, action: str) -> None:
    """Treat macOS's explicit missing-item result as an idempotent success."""
    if result.returncode == 0 or b"-25300" in result.standard_error:
        return
    raise TrustStoreError(f"Unable to {action}")
