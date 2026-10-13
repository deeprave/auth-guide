"""Server-owned PID and metadata lifecycle state."""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import anyio
from anyio import Path as AsyncPath


class LifecycleError(RuntimeError):
    """Raised when the local provider lifecycle state is not usable."""


@dataclass(frozen=True, slots=True)
class LifecyclePaths:
    """The server-owned files for one configured provider instance."""

    config_dir: AsyncPath

    @property
    def pid(self) -> AsyncPath:
        """Return the conventional decimal PID-file location."""
        return self.config_dir / "auth-guide.pid"

    @property
    def metadata(self) -> AsyncPath:
        """Return the additive JSON lifecycle metadata location."""
        return self.config_dir / "auth-guide.meta.json"

    @property
    def lock(self) -> AsyncPath:
        """Return the private advisory-lock location."""
        return self.config_dir / "auth-guide.lifecycle.lock"


@dataclass(frozen=True, slots=True)
class LifecycleState:
    """A non-secret snapshot of server-owned lifecycle state."""

    state: Literal["running", "starting", "stopped", "stale"]
    pid: int | None = None
    listen: str | None = None
    generation: int | None = None

    def as_json(self) -> str:
        """Encode structured status output without optional null values."""
        values: dict[str, object] = {"state": self.state}
        if self.pid is not None:
            values["pid"] = self.pid
        if self.listen is not None:
            values["listen"] = self.listen
        if self.generation is not None:
            values["generation"] = self.generation
        return json.dumps(values, sort_keys=True)


class LifecycleLock:
    """An owned async facade for the short critical sections around lifecycle files."""

    def __init__(self, paths: LifecyclePaths) -> None:
        self._paths = paths
        self._stream: anyio.AsyncFile[bytes] | None = None

    async def __aenter__(self) -> "LifecycleLock":
        """Acquire the advisory lock without blocking the event loop."""
        await self._paths.config_dir.mkdir(parents=True, exist_ok=True)
        self._stream = await self._paths.lock.open("ab")
        descriptor = self._stream.wrapped.fileno()
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                await anyio.sleep(0.02)

    async def __aexit__(self, *_: object) -> None:
        """Release the advisory lock and its owned stream."""
        stream = self._stream
        self._stream = None
        if stream is not None:
            fcntl.flock(stream.wrapped.fileno(), fcntl.LOCK_UN)
            await stream.aclose()


def process_is_live(pid: int) -> bool:
    """Return whether this host currently has the recorded process identifier."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OverflowError:
        return False
    except PermissionError:
        return True
    return True


async def read_state(paths: LifecyclePaths) -> LifecycleState:
    """Read lifecycle state without repairing or otherwise mutating it."""
    pid = await _read_pid(paths.pid)
    if pid is None:
        return LifecycleState("stopped")
    if not process_is_live(pid):
        return LifecycleState("stale", pid=pid)
    metadata = await _read_metadata(paths.metadata)
    if metadata is None:
        return LifecycleState("starting", pid=pid)
    listen = metadata.get("listen")
    generation = metadata.get("generation")
    if not isinstance(listen, str) or not isinstance(generation, int):
        raise LifecycleError("Server lifecycle metadata is invalid")
    state: Literal["running", "starting"] = "running" if generation > 0 else "starting"
    return LifecycleState(state, pid=pid, listen=listen, generation=generation)


async def begin_runtime(paths: LifecyclePaths, listen: str) -> None:
    """Claim lifecycle state for a newly launched server runtime."""
    async with LifecycleLock(paths):
        state = await read_state(paths)
        if state.state in {"running", "starting"}:
            raise LifecycleError("auth-guide server is already running")
        if state.state == "stale":
            await _unlink_if_present(paths.pid)
        await _unlink_if_present(paths.metadata)
        await _write_pid_exclusively(paths.pid, os.getpid())
        try:
            await _write_metadata(paths.metadata, listen=listen, generation=0)
        except BaseException:
            await _unlink_if_present(paths.pid)
            raise


async def mark_ready(paths: LifecyclePaths, listen: str, generation: int) -> None:
    """Publish one completed readiness transition for the current server."""
    async with LifecycleLock(paths):
        await _write_metadata(paths.metadata, listen=listen, generation=generation)


async def end_runtime(paths: LifecyclePaths) -> None:
    """Remove only this server's lifecycle state in safe shutdown order."""
    async with LifecycleLock(paths):
        pid = await _read_pid(paths.pid)
        if pid == os.getpid():
            await _unlink_if_present(paths.metadata)
            await _unlink_if_present(paths.pid)


async def _read_pid(path: AsyncPath) -> int | None:
    try:
        contents = (await path.read_text(encoding="ascii")).strip()
    except FileNotFoundError:
        return None
    try:
        pid = int(contents)
    except ValueError as error:
        raise LifecycleError("Server PID file is invalid") from error
    if pid <= 0:
        raise LifecycleError("Server PID file is invalid")
    return pid


async def _read_metadata(path: AsyncPath) -> dict[str, object] | None:
    try:
        contents = await path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        value = json.loads(contents)
    except json.JSONDecodeError as error:
        raise LifecycleError("Server lifecycle metadata is invalid") from error
    if not isinstance(value, dict):
        raise LifecycleError("Server lifecycle metadata is invalid")
    return value


async def _write_pid_exclusively(path: AsyncPath, pid: int) -> None:
    try:
        async with await path.open("x", encoding="ascii") as stream:
            await stream.write(f"{pid}\n")
    except FileExistsError as error:
        raise LifecycleError("auth-guide server is already running") from error


async def _write_metadata(path: AsyncPath, *, listen: str, generation: int) -> None:
    temporary = AsyncPath(f"{path}.tmp-{os.getpid()}")
    try:
        async with await temporary.open("x", encoding="utf-8") as stream:
            await stream.write(json.dumps({"listen": listen, "generation": generation}, sort_keys=True))
        await temporary.replace(path)
    finally:
        await _unlink_if_present(temporary)


async def _unlink_if_present(path: AsyncPath) -> None:
    try:
        await path.unlink()
    except FileNotFoundError:
        return


def paths_for(config_dir: str | Path | AsyncPath) -> LifecyclePaths:
    """Create lifecycle paths from the provider configuration directory."""
    return LifecyclePaths(AsyncPath(config_dir))
