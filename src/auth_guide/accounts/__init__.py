"""Encrypted asynchronous provider account persistence."""

from __future__ import annotations

import asyncio
import base64
import secrets
from pathlib import Path
from typing import Any

from anyio import Path as AsyncPath
from tortoise import Tortoise
from tortoise.connection import get_connection
from tortoise.migrations.api import migrate
from tortoise.migrations.executor import MigrationExecutor

from auth_guide.accounts.models import AccountRecord, Grant
from auth_guide.accounts.passwords import PasswordOperations
from auth_guide.secrets import (
    PlatformSecretProvider,
    SecretAlreadyExistsError,
    SecretReference,
)

DATABASE_KEY_REFERENCE = SecretReference("auth-guide-database-key")
DATABASE_FILENAME = "auth-guide.sqlite3"

__all__ = [
    "AccountRecord",
    "AccountStore",
    "AccountStoreError",
    "DATABASE_FILENAME",
    "Grant",
]


class AccountStoreError(RuntimeError):
    """Base error for account-store lifecycle and persistence failures."""


class AccountStore:
    """Own the encrypted Tortoise connection and account-password operations."""

    def __init__(self, config_dir: str | Path | AsyncPath, secrets_provider: PlatformSecretProvider) -> None:
        self._config_dir = AsyncPath(config_dir)
        self._secrets = secrets_provider
        self._passwords = PasswordOperations()
        self._database_key: bytes | None = None
        self._started = False
        self._migrated = False

    async def __aenter__(self) -> "AccountStore":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def start(self) -> None:
        """Configure encrypted storage without applying database migrations."""
        if self._started:
            return
        await self._config_dir.mkdir(parents=True, exist_ok=True)
        self._database_key = await self._resolve_database_key()
        await self._passwords.start()
        try:
            await Tortoise.init(config=self._tortoise_config(), init_connections=False)
            self._started = True
        except BaseException:
            await self._passwords.aclose()
            self._database_key = None
            raise

    async def initialise(self) -> None:
        """Explicitly create a new encrypted account database from user migrations."""
        if self._started:
            raise AccountStoreError("Account store is already started")
        await self._config_dir.mkdir(parents=True, exist_ok=True)
        if await self._database_path.exists():
            raise AccountStoreError("Account database already exists")
        if not await self._has_user_migrations():
            raise AccountStoreError("Account store migration is required")
        key = secrets.token_bytes(32)
        try:
            creation_cancelled = await self._create_database_key(key)
        except SecretAlreadyExistsError as error:
            raise AccountStoreError("Account database key already exists") from error
        try:
            created_database_key = True
            if creation_cancelled:
                raise asyncio.CancelledError
            self._database_key = key
            await self._passwords.start()
            await Tortoise.init(config=self._tortoise_config(), init_connections=False)
            self._started = True
            await migrate(config=self._tortoise_config())
            await Tortoise.init(config=self._tortoise_config())
            self._migrated = True
        except BaseException:
            await self._cleanup_failed_initialisation(created_database_key)
            raise

    async def aclose(self) -> None:
        """Close database connections owned by this store."""
        if self._started:
            await Tortoise.close_connections()
            await self._passwords.aclose()
            self._started = False
            self._migrated = False

    async def apply_migrations(self) -> None:
        """Explicitly apply the deploying user's native Tortoise migrations."""
        await self._require_started()
        if not await self._database_path.exists():
            raise AccountStoreError("Account database is not initialised")
        if not await self._has_user_migrations():
            raise AccountStoreError("Account store migration is required")
        await migrate(config=self._tortoise_config())
        await Tortoise.init(config=self._tortoise_config())
        self._migrated = True

    async def migration_required(self) -> bool:
        """Report whether native migrations are pending without applying them."""
        await self.pending_migration_plan()
        return not self._migrated

    async def pending_migration_plan(self) -> tuple[str, ...]:
        """Return a silent, display-ready plan of unapplied native migrations."""
        await self._require_started()
        if not await self._has_user_migrations():
            self._migrated = False
            return ()
        if not await self._database_path.exists():
            self._migrated = False
            return ()
        config = self._tortoise_config()
        connection = get_connection("default")
        await connection.create_connection(with_db=True)
        executor = MigrationExecutor(connection, config["apps"])
        steps = await executor.plan()
        migration_plan = tuple(
            f"{'-' if step.backward else '+'} {step.migration.app_label}.{step.migration.name}" for step in steps
        )
        self._migrated = not migration_plan
        return migration_plan

    async def list_accounts(self, *, include_inactive: bool = False) -> list[AccountRecord]:
        """Return complete account records, excluding inactive accounts by default."""
        await self._require_migrated()
        accounts = AccountRecord.including_inactive() if include_inactive else AccountRecord.all()
        return await accounts.order_by("email_comparison")

    async def set_password(self, account: AccountRecord, password: str) -> None:
        """Persist a fixed-policy Argon2id verifier on an account record."""
        await self._require_migrated()
        account.password_hash = await self._passwords.hash(password)
        await account.save(update_fields=["password_hash"])

    async def verify_password(self, account: AccountRecord | None, password: str) -> bool:
        """Verify an active account password against its fixed Argon2id policy."""
        await self._require_migrated()
        if account is None or account.password_hash is None:
            await self._passwords.verify_unknown(password)
            return False
        if not account.is_active:
            await self._passwords.verify_unknown(password)
            return False
        if not await self._passwords.verify(account.password_hash, password):
            return False
        current_account = await AccountRecord.get_or_none(id=account.id)
        return (
            current_account is not None
            and current_account.is_active
            and current_account.password_hash == account.password_hash
        )

    async def _cleanup_failed_initialisation(self, created_database_key: bool) -> None:
        """Close partial state and remove a key created by this failed invocation."""
        try:
            if self._started:
                await self.aclose()
            else:
                await self._passwords.aclose()
        finally:
            self._started = False
            self._migrated = False
            self._database_key = None
            for database_path in self._database_files:
                if await database_path.exists():
                    await database_path.unlink()
            if created_database_key:
                await self._secrets.delete(DATABASE_KEY_REFERENCE)

    async def _create_database_key(self, key: bytes) -> bool:
        """Create a key to completion and report whether the caller cancelled."""
        creation = asyncio.create_task(
            self._secrets.create(DATABASE_KEY_REFERENCE, base64.b64encode(key).decode("ascii"))
        )
        cancelled = False
        while not creation.done():
            try:
                await asyncio.shield(creation)
            except asyncio.CancelledError:
                cancelled = True
        await creation
        return cancelled

    async def _resolve_database_key(self) -> bytes:
        encoded_key = await self._secrets.resolve(DATABASE_KEY_REFERENCE)
        try:
            key = base64.b64decode(encoded_key, validate=True)
        except ValueError as error:
            raise AccountStoreError("Stored database key is invalid") from error
        if len(key) != 32:
            raise AccountStoreError("Stored database key is invalid")
        return key

    async def _require_started(self) -> None:
        if not self._started:
            raise AccountStoreError("Account store is not started")

    async def _require_migrated(self) -> None:
        await self._require_started()
        if not self._migrated:
            raise AccountStoreError("Account store migration is required")

    async def _has_user_migrations(self) -> bool:
        """Report whether the deploying user has supplied a native migration."""
        migrations_path = AsyncPath(__file__).parent / "migrations"
        async for path in migrations_path.iterdir():
            if path.suffix == ".py" and path.name != "__init__.py" and not path.name.startswith("_"):
                return True
        return False

    @property
    def _database_path(self) -> AsyncPath:
        """Return the configured encrypted database path."""
        return self._config_dir / DATABASE_FILENAME

    @property
    def _database_files(self) -> tuple[AsyncPath, AsyncPath, AsyncPath]:
        """Return the database file and SQLite write-ahead-log sidecars."""
        database_path = self._database_path
        return database_path, AsyncPath(f"{database_path}-wal"), AsyncPath(f"{database_path}-shm")

    def _tortoise_config(self) -> dict[str, Any]:
        key = self._database_key
        if key is None:
            raise AccountStoreError("Account store database key is unavailable")
        return {
            "use_tz": True,
            "timezone": "UTC",
            "connections": {
                "default": {
                    "engine": "tortoise_sqlcipher.sqlite_sqlcipher",
                    "credentials": {
                        "file_path": str(self._database_path),
                        "encryption_key": key,
                    },
                }
            },
            "apps": {
                "accounts": {
                    "models": ["auth_guide.accounts.models"],
                    "migrations": "auth_guide.accounts.migrations",
                }
            },
        }
