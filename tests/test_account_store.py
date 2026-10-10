"""Behaviour tests for the provider account model and storage lifecycle."""

from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from anyio import Path

from auth_guide.accounts import (
    DATABASE_FILENAME,
    AccountRecord,
    AccountStore,
    AccountStoreError,
    AccountTokenRecord,
    Grant,
    generate_account_token,
    verify_account_token,
)
from auth_guide.accounts.models import normalise_account_email, normalise_grants
from auth_guide.secrets import MissingSecretError, PlatformSecretProvider, SecretReference


@dataclass
class MemoryKeyring:
    """A keyring double for provider-owned database-key behaviour."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        del self.values[(service_name, username)]


@pytest.mark.anyio
async def test_account_record_exposes_all_metadata_and_effective_grants() -> None:
    """An account record retains ordinary profile and lifecycle state."""
    account = AccountRecord(
        id=uuid4(),
        email="member@example.com",
        email_comparison="member@example.com",
        grants=[Grant.GUIDE_ADMIN, Grant.ACCOUNTS_MANAGE],
        password_hash="verifier",
        created_at=datetime.now(timezone.utc),
        expires_at=None,
        full_name="Ada Lovelace",
        must_change_password=False,
    )

    assert account.full_name == "Ada Lovelace"
    assert account.created_at.utcoffset() == timedelta(0)
    assert account.is_active
    assert account.has_grant(Grant.GUIDE_ADMIN)
    assert account.has_grant(Grant.ACCOUNTS_MANAGE)
    assert not account.has_grant(Grant.ACCOUNTS_READ)


@pytest.mark.anyio
async def test_expired_account_retains_its_record_but_has_no_effective_grant() -> None:
    """Expiry affects access only; it does not remove account metadata."""
    account = AccountRecord(
        id=uuid4(),
        email="expired@example.com",
        email_comparison="expired@example.com",
        grants=[Grant.ACCOUNTS_READ],
        password_hash="verifier",
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        full_name=None,
    )

    assert not account.is_active
    assert not account.has_grant(Grant.ACCOUNTS_READ)
    assert account.email == "expired@example.com"


@pytest.mark.anyio
async def test_email_normalisation_preserves_the_local_part_and_normalises_domain() -> None:
    """Account model validation is syntax-only and does not alter local spelling."""
    values = await normalise_account_email("e\u0301xample@EXAMPLE.com")

    assert values == {
        "email": "e\u0301xample@example.com",
        "email_comparison": "e\u0301xample@example.com",
    }


@pytest.mark.anyio
async def test_grant_sets_accept_only_recognised_unique_values() -> None:
    """Grant persistence preserves a complete, valid capability set."""
    assert await normalise_grants([Grant.GUIDE_ADMIN, "tokens:manage"]) == [
        "guide:admin",
        "tokens:manage",
    ]

    with pytest.raises(ValueError, match="unknown grant"):
        await normalise_grants(["future:capability"])

    with pytest.raises(ValueError, match="must not contain duplicates"):
        await normalise_grants(["accounts:read", "accounts:read"])


@pytest.mark.anyio
async def test_account_token_record_keeps_only_non_secret_token_metadata() -> None:
    """The persisted token record contains a verifier but never its raw bearer."""
    token = AccountTokenRecord(
        id=uuid4(),
        account_id=uuid4(),
        label="laptop",
        verifier="0" * 64,
        scopes=[Grant.ACCOUNTS_READ],
        created_at=datetime.now(timezone.utc),
    )

    assert token.label == "laptop"
    assert token.verifier == "0" * 64
    assert token.scopes == [Grant.ACCOUNTS_READ]
    assert not hasattr(token, "token")


@pytest.mark.anyio
async def test_generated_account_token_is_opaque_and_verifies_only_its_own_value() -> None:
    """A raw token is prefixed, 256-bit opaque material with verifier-only storage."""
    token = await generate_account_token()

    assert token.raw_value.startswith("agt_")
    assert len(token.raw_value.removeprefix("agt_")) == 43
    assert len(token.verifier) == 64
    assert await verify_account_token(token.raw_value, token.verifier)
    assert not await verify_account_token(f"{token.raw_value}x", token.verifier)


@pytest.mark.anyio
async def test_existing_database_without_its_key_fails_without_replacement(tmp_path) -> None:
    """A missing platform key does not silently strand an existing database."""
    database_path = Path(tmp_path) / DATABASE_FILENAME
    await database_path.write_bytes(b"existing encrypted database")
    async with PlatformSecretProvider("account-store", MemoryKeyring()) as secrets:
        store = AccountStore(Path(tmp_path), secrets)

        with pytest.raises(MissingSecretError, match="auth-guide-database-key"):
            await store.start()


@pytest.mark.anyio
async def test_readiness_does_not_create_a_missing_database(tmp_path) -> None:
    """Readiness leaves first-time database creation to explicit migration."""
    database_path = Path(tmp_path) / DATABASE_FILENAME
    async with PlatformSecretProvider("account-store", MemoryKeyring()) as secrets:
        await secrets.store(SecretReference("auth-guide-database-key"), b64encode(b"0" * 32).decode("ascii"))
        async with AccountStore(Path(tmp_path), secrets) as store:
            assert await store.migration_required()

    assert not await database_path.exists()


@pytest.mark.anyio
async def test_initialise_refuses_to_replace_an_existing_database(tmp_path) -> None:
    """Database creation is an explicit one-time initialisation operation."""
    database_path = Path(tmp_path) / DATABASE_FILENAME
    await database_path.write_bytes(b"existing encrypted database")
    async with PlatformSecretProvider("account-store", MemoryKeyring()) as secrets:
        store = AccountStore(Path(tmp_path), secrets)

        with pytest.raises(AccountStoreError, match="database already exists"):
            await store.initialise()
