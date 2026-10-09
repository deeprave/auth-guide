"""Account-password operations behind an owned asynchronous boundary."""

from __future__ import annotations

import asyncio
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar, cast

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

__all__ = ["PasswordOperations", "PasswordOperationsClosedError", "PasswordOperationsError"]

ResultT = TypeVar("ResultT")


class PasswordOperationsError(RuntimeError):
    """Base error for the password operations boundary."""


class PasswordOperationsClosedError(PasswordOperationsError):
    """Raised when password work is requested outside the worker lifecycle."""


@dataclass(slots=True)
class _Outcome:
    value: object | None = None
    error: BaseException | None = None


@dataclass(slots=True)
class _Call:
    operation: Callable[[], object]
    loop: asyncio.AbstractEventLoop
    completion: asyncio.Future[_Outcome]


@dataclass(slots=True)
class _Stop:
    loop: asyncio.AbstractEventLoop
    completion: asyncio.Future[None]


class PasswordOperations:
    """Run Argon2id work through one owned serial worker."""

    def __init__(self) -> None:
        self._hasher = PasswordHasher(
            time_cost=3,
            memory_cost=64 * 1024,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._calls: queue.Queue[_Call | _Stop] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._closed = False
        self._shutdown_completion: asyncio.Future[None] | None = None

    async def __aenter__(self) -> "PasswordOperations":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def start(self) -> None:
        """Start the password operations worker."""
        if self._closed:
            raise PasswordOperationsClosedError("Password operations worker is closed")
        if self._worker is None:
            self._worker = threading.Thread(target=self._run, name="auth-guide-passwords", daemon=True)
            self._worker.start()

    async def verify_unknown(self, password: str) -> None:
        """Perform an equivalent password verification for an absent account."""
        await self.verify(
            "$argon2id$v=19$m=65536,t=3,p=4$MDEyMzQ1Njc4OWFiY2RlZg$PjSoTrIgSEYn0GfJ1m5dwCJmQtOaMjFFTIwHP6GJwrs",
            password,
        )

    async def aclose(self) -> None:
        """Stop through a shared cancellation-safe shutdown operation."""
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
                completion.set_exception(PasswordOperationsError("Password operations worker stopped unexpectedly"))
        await asyncio.shield(completion)

    async def hash(self, password: str) -> str:
        """Create one current-policy Argon2id verifier."""
        return await self._call(lambda: self._hasher.hash(password))

    async def verify(self, verifier: str, password: str) -> bool:
        """Verify a password against its fixed-policy Argon2id verifier."""

        def operation() -> bool:
            try:
                return self._hasher.verify(verifier, password)
            except (InvalidHashError, VerificationError):
                return False

        return await self._call(operation)

    async def _call(self, operation: Callable[[], ResultT]) -> ResultT:
        worker = self._worker
        if self._closed or worker is None or not worker.is_alive():
            raise PasswordOperationsClosedError("Password operations worker is not running")
        loop = asyncio.get_running_loop()
        completion: asyncio.Future[_Outcome] = loop.create_future()
        self._calls.put(_Call(operation, loop, completion))
        outcome = await asyncio.shield(completion)
        if outcome.error is not None:
            raise outcome.error
        return cast(ResultT, outcome.value)

    def _run(self) -> None:
        stop: _Stop | None = None
        try:
            while True:
                item = self._calls.get()
                if isinstance(item, _Stop):
                    stop = item
                    return
                try:
                    outcome = _Outcome(value=item.operation())
                except BaseException as error:
                    outcome = _Outcome(error=error)
                item.loop.call_soon_threadsafe(_complete_call, item.completion, outcome)
        finally:
            if stop is not None:
                stop.loop.call_soon_threadsafe(_complete_shutdown, stop.completion)


def _complete_call(completion: asyncio.Future[_Outcome], outcome: _Outcome) -> None:
    if not completion.done():
        completion.set_result(outcome)


def _complete_shutdown(completion: asyncio.Future[None]) -> None:
    if not completion.done():
        completion.set_result(None)
