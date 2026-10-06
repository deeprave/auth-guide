"""Async access to provider-owned secrets in the platform keyring."""

import asyncio
import logging
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TypeVar, cast

import keyring
from keyring.errors import KeyringError

__all__ = [
    "MissingSecretError",
    "PlatformSecretProvider",
    "SecretProviderClosedError",
    "SecretProviderError",
    "SecretReference",
]

logger = logging.getLogger(__name__)


class Keyring(Protocol):
    """The keyring operations required by the provider."""

    def get_password(self, service_name: str, username: str) -> str | None:
        del service_name, username
        raise NotImplementedError

    def set_password(self, service_name: str, username: str, password: str) -> None:
        del service_name, username, password
        raise NotImplementedError

    def delete_password(self, service_name: str, username: str) -> None:
        del service_name, username
        raise NotImplementedError


class SecretProviderError(RuntimeError):
    """Base error whose own message never contains a secret value."""


class MissingSecretError(SecretProviderError):
    """Raised when a configured secret reference cannot be resolved."""


class SecretProviderClosedError(SecretProviderError):
    """Raised when an operation is attempted after shutdown."""


@dataclass(frozen=True, slots=True)
class SecretReference:
    """An opaque name for one provider-owned secret."""

    name: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            msg = "Secret reference must not be blank"
            raise ValueError(msg)


ResultT = TypeVar("ResultT")


@dataclass(slots=True)
class _CallOutcome:
    value: object | None = None
    error: BaseException | None = None


@dataclass(slots=True)
class _KeyringCall:
    operation: Callable[[], object]
    loop: asyncio.AbstractEventLoop
    completion: asyncio.Future[_CallOutcome]
    mutation_lock: threading.Lock | None
    mutation_cancelled: bool = False

    def cancel_pending_mutation(self) -> None:
        """Record cancellation while atomically preserving a prior worker claim."""
        if self.mutation_lock is not None:
            with self.mutation_lock:
                self.mutation_cancelled = True

    def claim_mutation(self) -> bool:
        """Claim a mutation unless cancellation reached the queue boundary first."""
        if self.mutation_lock is None:
            return True
        with self.mutation_lock:
            if self.mutation_cancelled:
                return False
            return True

    def was_cancelled_mutation(self) -> bool:
        """Return whether the awaiting caller cancelled a mutation."""
        if self.mutation_lock is None:
            return False
        with self.mutation_lock:
            return self.mutation_cancelled


@dataclass(slots=True)
class _Stop:
    loop: asyncio.AbstractEventLoop
    completion: asyncio.Future[None]


class PlatformSecretProvider:
    """Resolve provider secrets through one private serial keyring worker."""

    def __init__(self, namespace: str, keyring_module: Keyring | None = None) -> None:
        if not namespace.strip():
            msg = "Secret namespace must not be blank"
            raise ValueError(msg)
        self._namespace = namespace
        self._keyring = keyring_module or keyring
        self._calls: queue.Queue[_KeyringCall | _Stop] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._closed = False
        self._shutdown_completion: asyncio.Future[None] | None = None

    @property
    def is_running(self) -> bool:
        """Whether the provider worker is accepting operations."""
        return self._worker is not None and self._worker.is_alive() and not self._closed

    async def __aenter__(self) -> "PlatformSecretProvider":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def start(self) -> None:
        """Start the private keyring worker."""
        if self._closed:
            raise SecretProviderClosedError("Platform secret provider is closed")
        if self._worker is None:
            self._worker = threading.Thread(target=self._run, name="auth-guide-keyring", daemon=True)
            self._worker.start()

    async def aclose(self) -> None:
        """Stop work through one shared, cancellation-safe shutdown operation."""
        completion = self._shutdown_completion
        if completion is None:
            loop = asyncio.get_running_loop()
            completion = loop.create_future()
            self._shutdown_completion = completion
            self._closed = True
            worker = self._worker
            if worker is None:
                completion.set_result(None)
            elif worker.is_alive():
                self._calls.put(_Stop(loop, completion))
            else:
                completion.set_exception(SecretProviderError("Platform secret worker stopped unexpectedly"))

        await asyncio.shield(completion)

    async def resolve(self, reference: SecretReference) -> str:
        """Resolve one configured secret without retaining its value."""
        value = await self._call(
            lambda: self._keyring.get_password(self._namespace, reference.name),
            is_mutation=False,
        )
        if value is None:
            raise MissingSecretError(f"Secret reference is unavailable: {reference.name}")
        return str(value)

    async def store(self, reference: SecretReference, value: str) -> None:
        """Create or replace one secret at its opaque reference."""
        await self._call(
            lambda: self._keyring.set_password(self._namespace, reference.name, value),
            is_mutation=True,
        )

    async def delete(self, reference: SecretReference) -> None:
        """Remove one secret from the platform keyring."""
        await self._call(
            lambda: self._keyring.delete_password(self._namespace, reference.name),
            is_mutation=True,
        )

    async def _call(self, operation: Callable[[], ResultT], *, is_mutation: bool) -> ResultT:
        if not self.is_running:
            raise SecretProviderClosedError("Platform secret provider is not running")
        loop = asyncio.get_running_loop()
        completion: asyncio.Future[_CallOutcome] = loop.create_future()
        mutation_lock = threading.Lock() if is_mutation else None
        call = _KeyringCall(operation, loop, completion, mutation_lock)
        self._calls.put(call)

        try:
            outcome = await asyncio.shield(completion)
        except asyncio.CancelledError:
            call.cancel_pending_mutation()
            raise

        if outcome.error is not None:
            self._raise_operation_error(outcome.error)
        return cast(ResultT, outcome.value)

    @staticmethod
    def _raise_operation_error(error: BaseException) -> None:
        if isinstance(error, KeyringError):
            raise error
        raise SecretProviderError("Platform keyring operation failed") from error

    def _run(self) -> None:
        stop: _Stop | None = None
        try:
            while True:
                item = self._calls.get()
                if isinstance(item, _Stop):
                    stop = item
                    item = None
                    return
                if not item.claim_mutation():
                    item.loop.call_soon_threadsafe(_set_result, item.completion, _CallOutcome())
                else:
                    self._run_call(item)
                item = None
        finally:
            if stop is not None:
                stop.loop.call_soon_threadsafe(_complete_shutdown, stop.completion)

    @staticmethod
    def _run_call(call: _KeyringCall) -> None:
        try:
            outcome = _CallOutcome(value=call.operation())
        except BaseException as error:
            if call.was_cancelled_mutation():
                logger.warning("Cancelled platform keyring mutation failed: %s", type(error).__name__)
                outcome = _CallOutcome()
            else:
                outcome = _CallOutcome(error=error)
        call.loop.call_soon_threadsafe(_set_result, call.completion, outcome)


def _set_result(completion: asyncio.Future[_CallOutcome], outcome: _CallOutcome) -> None:
    if not completion.done():
        completion.set_result(outcome)


def _complete_shutdown(completion: asyncio.Future[None]) -> None:
    if not completion.done():
        completion.set_result(None)
