"""Owned asynchronous boundary for synchronous certificate operations."""

from __future__ import annotations

import asyncio
import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar, cast

__all__ = ["CertificateOperations", "CertificateOperationsClosedError", "CertificateOperationsError"]

ResultT = TypeVar("ResultT")


class CertificateOperationsError(RuntimeError):
    """Base error for the certificate operations boundary."""


class CertificateOperationsClosedError(CertificateOperationsError):
    """Raised when operations are attempted outside the worker lifecycle."""


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


class CertificateOperations:
    """Run synchronous cryptographic work through one owned serial worker."""

    def __init__(self) -> None:
        self._calls: queue.Queue[_Call | _Stop] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._closed = False
        self._shutdown_completion: asyncio.Future[None] | None = None

    @property
    def is_running(self) -> bool:
        """Whether the worker is accepting certificate operations."""
        return self._worker is not None and self._worker.is_alive() and not self._closed

    async def __aenter__(self) -> "CertificateOperations":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def start(self) -> None:
        """Start the certificate operations worker."""
        if self._closed:
            raise CertificateOperationsClosedError("Certificate operations worker is closed")
        if self._worker is None:
            self._worker = threading.Thread(target=self._run, name="auth-guide-certificates", daemon=True)
            self._worker.start()

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
                completion.set_exception(
                    CertificateOperationsError("Certificate operations worker stopped unexpectedly")
                )
        await asyncio.shield(completion)

    async def call(self, operation: Callable[[], ResultT]) -> ResultT:
        """Run one synchronous certificate operation without blocking the caller."""
        if not self.is_running:
            raise CertificateOperationsClosedError("Certificate operations worker is not running")
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
