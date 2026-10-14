"""End-to-end behaviour for explicit local provider initialisation."""

from dataclasses import dataclass, field

import pytest
from anyio import Path as AsyncPath

from auth_guide.accounts import DATABASE_FILENAME, AccountStore
from auth_guide.bootstrap import initialise_provider
from auth_guide.secrets import MissingSecretError, PlatformSecretProvider, SecretReference


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

    assert not await (AsyncPath(tmp_path) / DATABASE_FILENAME).exists()
    async with PlatformSecretProvider("auth-guide", keyring) as secrets:
        with pytest.raises(MissingSecretError):
            await secrets.resolve(SecretReference("auth-guide-database-key"))
