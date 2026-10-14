"""Local first-administrator initialisation for a provider configuration root."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from anyio import Path as AsyncPath

from auth_guide.accounts import (
    AccountRecord,
    AccountStore,
    AccountStoreError,
    AccountTokenRecord,
    Grant,
    generate_account_token,
)
from auth_guide.accounts.models import normalise_account_email
from auth_guide.secrets import PlatformSecretProvider


@dataclass(frozen=True, slots=True)
class InitialProviderCredentials:
    """The once-only credentials produced by local provider initialisation."""

    password: str
    token: str


async def initialise_provider(
    config_dir: str | Path | AsyncPath,
    email: str,
    remove_orphan_key: bool = False,
) -> InitialProviderCredentials:
    """Create the encrypted store and first administrator only through local CLI setup."""
    try:
        email_values = await normalise_account_email(email)
    except ValueError as error:
        raise AccountStoreError(str(error)) from error

    async with PlatformSecretProvider("auth-guide") as secrets_provider:
        store = AccountStore(config_dir, secrets_provider)
        initialised = False
        try:
            if remove_orphan_key:
                await store.remove_orphan_database_key()
            await store.initialise()
            initialised = True
            password = _generate_initial_password()
            account = AccountRecord(
                email=email_values["email"],
                email_comparison=email_values["email_comparison"],
                grants=[Grant.GUIDE_ADMIN, Grant.ACCOUNTS_READ, Grant.ACCOUNTS_MANAGE, Grant.TOKENS_MANAGE],
            )
            await store.create_account(account, password)
            issued_token = await generate_account_token()
            await AccountTokenRecord.create(
                account=account,
                label="admin",
                verifier=issued_token.verifier,
                scopes=[Grant.ACCOUNTS_READ, Grant.ACCOUNTS_MANAGE, Grant.TOKENS_MANAGE],
            )
            return InitialProviderCredentials(password=password, token=issued_token.raw_value)
        except BaseException:
            if initialised:
                await store.rollback_initialisation()
            raise
        finally:
            await store.aclose()


def _generate_initial_password() -> str:
    """Generate the fixed 12-character printable-ASCII initial password."""
    printable_ascii = "".join(chr(value) for value in range(33, 127))
    return "".join(secrets.choice(printable_ascii) for _ in range(12))
