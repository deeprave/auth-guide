"""Tortoise models for encrypted account persistence."""

import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from email_validator import EmailNotValidError, validate_email
from tortoise import fields
from tortoise.backends.base.client import BaseDBAsyncClient
from tortoise.expressions import Q
from tortoise.manager import Manager
from tortoise.models import Model
from tortoise.queryset import QuerySet

from auth_guide.accounts.passwords import PasswordOperations

logger = logging.getLogger(__name__)


class Grant(StrEnum):
    """Recognised capability grants persisted for provider accounts."""

    GUIDE_ADMIN = "guide:admin"
    ACCOUNTS_READ = "accounts:read"
    ACCOUNTS_MANAGE = "accounts:manage"
    TOKENS_MANAGE = "tokens:manage"


class AccountQuerySet(QuerySet):
    """Warn when native bulk writes bypass account-model validation."""

    def update(self, **kwargs: object):
        logger.warning("Bulk account update bypasses AccountRecord.save validation")
        return super().update(**kwargs)

    def bulk_create(
        self,
        objects: Iterable[Any],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_fields: Iterable[str] | None = None,
        on_conflict: Iterable[str] | None = None,
    ) -> Any:
        logger.warning("Bulk account creation bypasses AccountRecord.save validation")
        return super().bulk_create(objects, batch_size, ignore_conflicts, update_fields, on_conflict)

    def bulk_update(self, objects: Iterable[Any], fields: Iterable[str], batch_size: int | None = None) -> Any:
        logger.warning("Bulk account update bypasses AccountRecord.save validation")
        return super().bulk_update(objects, fields, batch_size)


class ActiveAccountManager(Manager):
    """Provide active accounts through the normal model query interface."""

    def get_queryset(self) -> QuerySet:
        """Return accounts whose optional expiry permits access now."""
        if self._model is None:
            raise RuntimeError("Account manager has no model")
        return AccountQuerySet(self._model).filter(Q(expires_at=None) | Q(expires_at__gt=datetime.now(timezone.utc)))


class AccountRecord(Model):
    """The persisted representation of one provider account."""

    id = fields.UUIDField(primary_key=True)
    email = fields.CharField(max_length=254)
    email_comparison = fields.CharField(max_length=254, unique=True)
    grants = fields.JSONField()
    password_hash = fields.TextField()
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField(null=True)
    full_name = fields.TextField(null=True)
    must_change_password = fields.BooleanField(default=False)

    class Meta:
        table = "accounts"
        manager = ActiveAccountManager()

    @classmethod
    def including_inactive(cls) -> QuerySet:
        """Return an unfiltered account query for explicit administration work."""
        return AccountQuerySet(cls)

    @property
    def is_active(self) -> bool:
        """Report whether the account's optional expiry permits access."""
        return self.expires_at is None or self.expires_at > datetime.now(timezone.utc)

    def has_grant(self, requested_grant: Grant) -> bool:
        """Report whether an active account holds the requested grant."""
        return self.is_active and requested_grant in self.grants

    async def save(
        self,
        using_db: BaseDBAsyncClient | None = None,
        update_fields: Iterable[str] | None = None,
        force_create: bool = False,
        force_update: bool = False,
    ) -> None:
        """Validate account identity and lifecycle fields before persistence."""
        fields_to_update = set(update_fields) if update_fields is not None else None
        if fields_to_update is None or "email" in fields_to_update:
            self.update_from_dict(await normalise_account_email(self.email))
            if fields_to_update is not None:
                fields_to_update.add("email_comparison")
        if fields_to_update is None or "expires_at" in fields_to_update:
            self.update_from_dict({"expires_at": await normalise_account_expiry(self.expires_at)})
        if fields_to_update is None or "grants" in fields_to_update:
            self.grants = await normalise_grants(self.grants)
        if fields_to_update is None or "password_hash" in fields_to_update:
            if self.password_hash is not None and not PasswordOperations.is_current_verifier(self.password_hash):
                raise ValueError("Account password verifier is invalid")
        await super().save(
            using_db=using_db,
            update_fields=fields_to_update,
            force_create=force_create,
            force_update=force_update,
        )


class AccountTokenRecord(Model):
    """A revocable account token represented only by its verifier and metadata."""

    id = fields.UUIDField(primary_key=True)
    account = fields.ForeignKeyField("accounts.AccountRecord", related_name="tokens", on_delete=fields.CASCADE)
    label = fields.TextField()
    verifier = fields.CharField(max_length=64, unique=True)
    scopes = fields.JSONField()
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "account_tokens"

    async def save(
        self,
        using_db: BaseDBAsyncClient | None = None,
        update_fields: Iterable[str] | None = None,
        force_create: bool = False,
        force_update: bool = False,
    ) -> None:
        """Validate immutable token properties and its mutable label."""
        fields_to_update = set(update_fields) if update_fields is not None else None
        if self._saved_in_db and (fields_to_update is None or fields_to_update - {"label"}):
            raise ValueError("Only an account token label may be updated")
        if fields_to_update is None or "label" in fields_to_update:
            if not self.label:
                raise ValueError("Account token label is required")
        if fields_to_update is None or "verifier" in fields_to_update:
            if len(self.verifier) != 64 or any(character not in "0123456789abcdef" for character in self.verifier):
                raise ValueError("Account token verifier is invalid")
        if fields_to_update is None or "scopes" in fields_to_update:
            self.scopes = await normalise_grants(self.scopes)
        await super().save(
            using_db=using_db,
            update_fields=fields_to_update,
            force_create=force_create,
            force_update=force_update,
        )


async def normalise_account_email(email: str) -> dict[str, str]:
    """Validate an email identifier without checking mailbox ownership."""
    try:
        validated = validate_email(email, check_deliverability=False)
    except EmailNotValidError as error:
        raise ValueError("Account email identifier is invalid") from error
    local_part, _, _ = validated.original.rpartition("@")
    canonical_email = f"{local_part}@{validated.domain.lower()}"
    if len(canonical_email.encode("utf-8")) > 254:
        raise ValueError("Account email identifier is too long")
    return {"email": canonical_email, "email_comparison": canonical_email.casefold()}


async def normalise_account_expiry(expires_at: datetime | None) -> datetime | None:
    """Validate and convert an optional account expiry to UTC."""
    if expires_at is None:
        return None
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise ValueError("Account expiry must include a timezone")
    return expires_at.astimezone(timezone.utc)


async def normalise_grants(grants: Iterable[Grant | str]) -> list[str]:
    """Validate a complete account grant or token scope set."""
    if isinstance(grants, str):
        raise ValueError("Grant set must be an array")
    values = list(grants)
    try:
        normalised = [str(Grant(value)) for value in values]
    except ValueError as error:
        raise ValueError("Grant set contains an unknown grant") from error
    if len(set(normalised)) != len(normalised):
        raise ValueError("Grant set must not contain duplicates")
    return normalised
