"""Behavioural tests for the platform secret provider."""

import asyncio
from dataclasses import dataclass, field
from platform import system
from threading import Event
from uuid import uuid4

import keyring
import pytest
from keyring.errors import NoKeyringError

from auth_guide.secrets import (
    MissingSecretError,
    PlatformSecretProvider,
    SecretAlreadyExistsError,
    SecretProviderError,
    SecretReference,
)


@dataclass
class MemoryKeyring:
    """A minimal keyring double that exercises the provider boundary."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        del self.values[(service_name, username)]


@dataclass
class BlockingKeyring(MemoryKeyring):
    """A keyring double that permits cancellation during a mutation."""

    release: Event = field(default_factory=Event)
    _started: asyncio.Event | None = field(default=None, init=False)
    _loop: asyncio.AbstractEventLoop | None = field(default=None, init=False)

    async def prepare(self) -> None:
        """Attach an asynchronous observation point before starting a mutation."""
        self._loop = asyncio.get_running_loop()
        self._started = asyncio.Event()

    async def wait_started(self) -> None:
        """Wait until the worker has entered a blocking mutation."""
        if self._started is None:
            raise RuntimeError("Blocking keyring was not prepared")
        await self._started.wait()

    def _signal_started(self) -> None:
        if self._loop is None or self._started is None:
            raise RuntimeError("Blocking keyring was not prepared")
        self._loop.call_soon_threadsafe(self._started.set)

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self._signal_started()
        self.release.wait()
        super().set_password(service_name, username, password)

    def delete_password(self, service_name: str, username: str) -> None:
        self._signal_started()
        self.release.wait()
        super().delete_password(service_name, username)


@dataclass
class FailingBlockingKeyring(BlockingKeyring):
    """A mutation double that fails after its caller has been cancelled."""

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self._signal_started()
        self.release.wait()
        del service_name, username, password
        raise RuntimeError("backend disclosed replacement-value")


class FailingKeyring:
    """A backend whose error text must not become provider diagnostics."""

    def get_password(self, service_name: str, username: str) -> str | None:
        del service_name, username
        raise RuntimeError("backend disclosed secret-value")

    def set_password(self, service_name: str, username: str, password: str) -> None:
        del service_name, username, password
        raise RuntimeError("backend disclosed secret-value")

    def delete_password(self, service_name: str, username: str) -> None:
        del service_name, username
        raise RuntimeError("backend disclosed secret-value")


class UnavailableKeyring:
    """A backend that reports its documented unavailable condition."""

    def get_password(self, service_name: str, username: str) -> str | None:
        del service_name, username
        raise NoKeyringError("keyring unavailable")

    def set_password(self, service_name: str, username: str, password: str) -> None:
        del service_name, username, password
        raise NoKeyringError("keyring unavailable")

    def delete_password(self, service_name: str, username: str) -> None:
        del service_name, username
        raise NoKeyringError("keyring unavailable")


def test_provider_resolves_namespaced_secret_without_retaining_it() -> None:
    async def exercise() -> None:
        secret = "value-that-must-not-appear-in-provider-repr"
        reference = SecretReference("database-key")
        keyring = MemoryKeyring()

        async with PlatformSecretProvider("auth-guide", keyring) as provider:
            await provider.store(reference, secret)

            assert await provider.resolve(reference) == secret
            assert secret not in repr(provider)

        assert not provider.is_running

    asyncio.run(exercise())


def test_missing_reference_raises_secret_safe_error() -> None:
    async def exercise() -> None:
        reference = SecretReference("missing-key")

        async with PlatformSecretProvider("auth-guide", MemoryKeyring()) as provider:
            with pytest.raises(MissingSecretError, match="missing-key") as error:
                await provider.resolve(reference)

        assert "secret-value" not in str(error.value)

    asyncio.run(exercise())


def test_concurrent_explicit_secret_creation_allows_one_creator() -> None:
    async def exercise() -> None:
        reference = SecretReference("database-key")
        keyring = MemoryKeyring()

        async with PlatformSecretProvider("auth-guide", keyring) as provider:
            first, second = await asyncio.gather(
                provider.create(reference, "first-initial-value"),
                provider.create(reference, "second-initial-value"),
                return_exceptions=True,
            )

        assert sum(result is None for result in (first, second)) == 1
        assert sum(isinstance(result, SecretAlreadyExistsError) for result in (first, second)) == 1
        assert keyring.values[("auth-guide", "database-key")] in {
            "first-initial-value",
            "second-initial-value",
        }

    asyncio.run(exercise())


def test_cancelled_mutation_completes_on_a_best_effort_basis() -> None:
    async def exercise() -> None:
        keyring = BlockingKeyring()
        await keyring.prepare()
        reference = SecretReference("issuer-key")

        async with PlatformSecretProvider("auth-guide", keyring) as provider:
            mutation = asyncio.create_task(provider.store(reference, "replacement-value"))
            try:
                await keyring.wait_started()
                mutation.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await mutation
            finally:
                keyring.release.set()

        assert keyring.values[("auth-guide", "issuer-key")] == "replacement-value"

    asyncio.run(exercise())


def test_cancelled_pending_mutation_does_not_run() -> None:
    async def exercise() -> None:
        keyring = BlockingKeyring()
        await keyring.prepare()
        first = SecretReference("first-key")
        pending = SecretReference("pending-key")

        async with PlatformSecretProvider("auth-guide", keyring) as provider:
            first_mutation = asyncio.create_task(provider.store(first, "first-value"))
            try:
                await keyring.wait_started()
                pending_mutation = asyncio.create_task(provider.store(pending, "pending-value"))
                await asyncio.sleep(0)
                pending_mutation.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending_mutation
            finally:
                keyring.release.set()
            await first_mutation

        assert ("auth-guide", "pending-key") not in keyring.values

    asyncio.run(exercise())


def test_cancelled_pending_delete_does_not_run() -> None:
    async def exercise() -> None:
        keyring = BlockingKeyring()
        await keyring.prepare()
        first = SecretReference("first-key")
        pending = SecretReference("pending-key")
        keyring.values[("auth-guide", pending.name)] = "pending-value"

        async with PlatformSecretProvider("auth-guide", keyring) as provider:
            first_mutation = asyncio.create_task(provider.store(first, "first-value"))
            try:
                await keyring.wait_started()
                pending_mutation = asyncio.create_task(provider.delete(pending))
                await asyncio.sleep(0)
                pending_mutation.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending_mutation
            finally:
                keyring.release.set()
            await first_mutation

        assert keyring.values[("auth-guide", "pending-key")] == "pending-value"

    asyncio.run(exercise())


def test_keyring_failure_does_not_expose_backend_diagnostics() -> None:
    async def exercise() -> None:
        async with PlatformSecretProvider("auth-guide", FailingKeyring()) as provider:
            with pytest.raises(SecretProviderError) as error:
                await provider.resolve(SecretReference("database-key"))

        assert "secret-value" not in str(error.value)
        assert isinstance(error.value.__cause__, RuntimeError)

    asyncio.run(exercise())


def test_documented_keyring_failure_is_preserved() -> None:
    async def exercise() -> None:
        async with PlatformSecretProvider("auth-guide", UnavailableKeyring()) as provider:
            with pytest.raises(NoKeyringError, match="unavailable"):
                await provider.resolve(SecretReference("database-key"))

    asyncio.run(exercise())


def test_closed_provider_rejects_every_public_operation() -> None:
    async def exercise() -> None:
        provider = PlatformSecretProvider("auth-guide", MemoryKeyring())
        reference = SecretReference("database-key")
        await provider.start()
        await provider.aclose()

        with pytest.raises(SecretProviderError, match="not running"):
            await provider.resolve(reference)
        with pytest.raises(SecretProviderError, match="not running"):
            await provider.store(reference, "replacement-value")
        with pytest.raises(SecretProviderError, match="not running"):
            await provider.create(reference, "initial-value")
        with pytest.raises(SecretProviderError, match="not running"):
            await provider.delete(reference)

    asyncio.run(exercise())


def test_cancelled_closer_does_not_abandon_shared_shutdown() -> None:
    async def exercise() -> None:
        keyring = BlockingKeyring()
        await keyring.prepare()
        provider = PlatformSecretProvider("auth-guide", keyring)
        reference = SecretReference("database-key")
        await provider.start()
        mutation = asyncio.create_task(provider.store(reference, "replacement-value"))
        try:
            await keyring.wait_started()

            cancelled_closer = asyncio.create_task(provider.aclose())
            surviving_closer = asyncio.create_task(provider.aclose())
            await asyncio.sleep(0)
            cancelled_closer.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled_closer

            keyring.release.set()
            await mutation
            await surviving_closer
        finally:
            keyring.release.set()
        assert not provider.is_running

    asyncio.run(exercise())


def test_cancelled_failed_mutation_logs_no_secret(caplog: pytest.LogCaptureFixture) -> None:
    async def exercise() -> None:
        keyring = FailingBlockingKeyring()
        await keyring.prepare()
        reference = SecretReference("database-key")

        async with PlatformSecretProvider("auth-guide", keyring) as provider:
            mutation = asyncio.create_task(provider.store(reference, "replacement-value"))
            try:
                await keyring.wait_started()
                mutation.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await mutation
            finally:
                keyring.release.set()

    asyncio.run(exercise())

    assert "Cancelled platform keyring mutation failed: RuntimeError" in caplog.messages
    assert "replacement-value" not in caplog.text


@pytest.mark.skipif(system() != "Darwin", reason="requires macOS Keychain")
def test_macos_keychain_create_replace_resolve_and_delete() -> None:
    async def exercise() -> None:
        namespace = f"auth-guide-test-{uuid4()}"
        reference = SecretReference(f"secret-{uuid4()}")
        provider = PlatformSecretProvider(namespace)
        deleted = False

        try:
            async with provider:
                await provider.store(reference, "first-value")
                assert await provider.resolve(reference) == "first-value"

                await provider.store(reference, "replacement-value")
                assert await provider.resolve(reference) == "replacement-value"

                await provider.delete(reference)
                deleted = True
                with pytest.raises(MissingSecretError):
                    await provider.resolve(reference)

            assert not provider.is_running
        finally:
            if not deleted:
                try:
                    keyring.delete_password(namespace, reference.name)
                except keyring.errors.KeyringError:
                    pass

    asyncio.run(exercise())


@pytest.mark.skipif(system() != "Linux", reason="requires Linux Freedesktop Secret Service")
def test_linux_secret_service_create_replace_resolve_and_delete() -> None:
    async def exercise() -> None:
        namespace = f"auth-guide-test-{uuid4()}"
        reference = SecretReference(f"secret-{uuid4()}")
        provider = PlatformSecretProvider(namespace)
        deleted = False

        assert type(keyring.get_keyring()).__module__ == "keyring.backends.SecretService"

        try:
            async with provider:
                await provider.store(reference, "first-value")
                assert await provider.resolve(reference) == "first-value"

                await provider.store(reference, "replacement-value")
                assert await provider.resolve(reference) == "replacement-value"

                await provider.delete(reference)
                deleted = True
                with pytest.raises(MissingSecretError):
                    await provider.resolve(reference)
        finally:
            if not deleted:
                try:
                    keyring.delete_password(namespace, reference.name)
                except keyring.errors.KeyringError:
                    pass

    asyncio.run(exercise())
