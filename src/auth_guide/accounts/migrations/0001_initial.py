import functools
from json import dumps, loads
from uuid import uuid4

from tortoise import fields, migrations
from tortoise.fields.base import OnDelete
from tortoise.migrations import operations as ops


class Migration(migrations.Migration):
    initial = True

    operations = [
        ops.CreateModel(
            name="AccountRecord",
            fields=[
                ("id", fields.UUIDField(primary_key=True, default=uuid4, unique=True, db_index=True)),
                ("email", fields.CharField(max_length=254)),
                ("email_comparison", fields.CharField(unique=True, max_length=254)),
                ("grants", fields.JSONField(encoder=functools.partial(dumps, separators=(",", ":")), decoder=loads)),
                ("password_hash", fields.TextField(unique=False)),
                ("created_at", fields.DatetimeField(auto_now=False, auto_now_add=True)),
                ("expires_at", fields.DatetimeField(null=True, auto_now=False, auto_now_add=False)),
                ("full_name", fields.TextField(null=True, unique=False)),
                ("must_change_password", fields.BooleanField(default=False)),
            ],
            options={
                "table": "accounts",
                "app": "accounts",
                "pk_attr": "id",
                "table_description": "The persisted representation of one provider account.",
            },
            bases=["Model"],
        ),
        ops.CreateModel(
            name="AccountTokenRecord",
            fields=[
                ("id", fields.UUIDField(primary_key=True, default=uuid4, unique=True, db_index=True)),
                (
                    "account",
                    fields.ForeignKeyField(
                        "accounts.AccountRecord",
                        source_field="account_id",
                        db_constraint=True,
                        to_field="id",
                        related_name="tokens",
                        on_delete=OnDelete.CASCADE,
                    ),
                ),
                ("label", fields.TextField(unique=False)),
                ("verifier", fields.CharField(unique=True, max_length=64)),
                ("scopes", fields.JSONField(encoder=functools.partial(dumps, separators=(",", ":")), decoder=loads)),
                ("created_at", fields.DatetimeField(auto_now=False, auto_now_add=True)),
            ],
            options={
                "table": "account_tokens",
                "app": "accounts",
                "pk_attr": "id",
                "table_description": "A revocable account token represented only by its verifier and metadata.",
            },
            bases=["Model"],
        ),
    ]
