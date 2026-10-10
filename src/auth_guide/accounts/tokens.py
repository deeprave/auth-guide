"""Opaque account access-token generation and verification."""

import secrets
from dataclasses import dataclass
from hashlib import sha256

from auth_guide.accounts.models import AccountTokenRecord


@dataclass(frozen=True)
class NewAccountToken:
    """A raw token available only while its issuing operation completes."""

    raw_value: str
    verifier: str


async def generate_account_token() -> NewAccountToken:
    """Generate one opaque 256-bit account token and its stored verifier."""
    raw_value = f"agt_{secrets.token_urlsafe(32)}"
    return NewAccountToken(raw_value=raw_value, verifier=hash_account_token(raw_value))


async def verify_account_token(raw_value: str, verifier: str) -> bool:
    """Compare a presented raw token with its persisted verifier."""
    return secrets.compare_digest(hash_account_token(raw_value), verifier)


async def resolve_account_token(raw_value: str) -> AccountTokenRecord | None:
    """Resolve a presented bearer to its active account token, if any."""
    if not raw_value.startswith("agt_"):
        return None
    token = await AccountTokenRecord.all().select_related("account").get_or_none(verifier=hash_account_token(raw_value))
    if token is None or not token.account.is_active:
        return None
    return token


def hash_account_token(raw_value: str) -> str:
    """Return the SHA-256 verifier for a raw account token."""
    return sha256(raw_value.encode("utf-8")).hexdigest()
