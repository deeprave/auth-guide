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
    """The one global grant persisted for each provider account."""

    USER = "user"
    ADMIN = "admin"


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
    grant = fields.CharField(max_length=5)
    password_hash = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField(null=True)
    full_name = fields.TextField(null=True)

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
        """Report whether an active account has an effective global grant."""
        grant = Grant(self.grant)
        return self.is_active and (grant == Grant.ADMIN or grant == requested_grant)

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
        if fields_to_update is None or "grant" in fields_to_update:
            try:
                Grant(self.grant)
            except ValueError as error:
                raise ValueError("Account grant is invalid") from error
        if fields_to_update is None or "password_hash" in fields_to_update:
            if self.password_hash is not None and not PasswordOperations.is_current_verifier(self.password_hash):
                raise ValueError("Account password verifier is invalid")
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
