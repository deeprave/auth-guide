"""End-to-end behaviour for explicit local provider initialisation."""

from dataclasses import dataclass, field

import pytest
from anyio import Path as AsyncPath

from auth_guide.accounts import AccountStore, database_key_reference
from auth_guide.bootstrap import initialise_provider
from auth_guide.provider import DEFAULT_NAMESPACE
from auth_guide.secrets import MissingSecretError, PlatformSecretProvider


@dataclass
class MemoryKeyring:
    """Provide process-local keyring storage for real bootstrap behaviour."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_password(self, service_name: str, username: str) -> str | None:
        """Return one stored secret."""
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        """Store one secret."""
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        """Remove one secret."""
        del self.values[(service_name, username)]


@pytest.mark.anyio
async def test_local_initialisation_creates_a_usable_first_administrator(tmp_path, monkeypatch) -> None:
    """Explicit local setup produces credentials and a migrated encrypted store."""
    import auth_guide.secrets as secrets_module

    keyring = MemoryKeyring()
    monkeypatch.setattr(secrets_module, "keyring", keyring)

    credentials = await initialise_provider(tmp_path, "administrator@example.com")

    assert len(credentials.password) == 12
    assert credentials.token.startswith("agt_")
    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        store = AccountStore(tmp_path, secrets)
        await store.start()
        assert not await store.migration_required()
        accounts = await store.list_accounts()
        assert [account.email for account in accounts] == ["administrator@example.com"]
        await store.aclose()


@pytest.mark.anyio
async def test_local_initialisation_scopes_the_database_to_its_namespace(tmp_path, monkeypatch) -> None:
    """An isolated provider initialises a database separate from the default namespace."""
    import auth_guide.secrets as secrets_module

    keyring = MemoryKeyring()
    monkeypatch.setattr(secrets_module, "keyring", keyring)

    await initialise_provider(tmp_path, "administrator@example.com", namespace="isolated-guide")

    assert await (AsyncPath(tmp_path) / "isolated-guide.sqlite3").exists()
    assert not await (AsyncPath(tmp_path) / f"{DEFAULT_NAMESPACE}.sqlite3").exists()
    async with PlatformSecretProvider("isolated-guide", keyring) as secrets:
        async with AccountStore(tmp_path, secrets) as store:
            assert not await store.migration_required()
            assert [account.email for account in await store.list_accounts()] == ["administrator@example.com"]


@pytest.mark.anyio
async def test_local_initialisation_rejects_an_unsafe_namespace(tmp_path) -> None:
    """Library callers cannot direct bootstrap state outside its storage root."""
    with pytest.raises(ValueError, match="Provider namespace must use only ASCII"):
        await initialise_provider(tmp_path, "administrator@example.com", namespace="../other")


@pytest.mark.anyio
async def test_local_initialisation_rolls_back_database_and_key_after_token_failure(tmp_path, monkeypatch) -> None:
    """A post-database bootstrap failure leaves neither encrypted store nor key behind."""
    import auth_guide.bootstrap as bootstrap_module
    import auth_guide.secrets as secrets_module

    keyring = MemoryKeyring()
    monkeypatch.setattr(secrets_module, "keyring", keyring)

    async def fail_token_generation():
        """Fail after the first account has been persisted."""
        raise RuntimeError("token persistence failed")

    monkeypatch.setattr(bootstrap_module, "generate_account_token", fail_token_generation)

    with pytest.raises(RuntimeError, match="token persistence failed"):
        await initialise_provider(tmp_path, "administrator@example.com")

    assert not await (AsyncPath(tmp_path) / f"{DEFAULT_NAMESPACE}.sqlite3").exists()
    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        with pytest.raises(MissingSecretError):
            await secrets.resolve(await database_key_reference(tmp_path, DEFAULT_NAMESPACE))
