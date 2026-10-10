"""Behaviour tests for the HTTPS management API application."""

import asyncio
import socket
import ssl
from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import cast

import httpx
import pytest
from anyio import Path as AsyncPath
from tortoise import Tortoise

import auth_guide.accounts as accounts_module
from auth_guide.accounts import (
    DATABASE_FILENAME,
    DATABASE_KEY_REFERENCE,
    AccountRecord,
    AccountStore,
    AccountStoreError,
    AccountTokenRecord,
    Grant,
    generate_account_token,
)
from auth_guide.accounts.passwords import PasswordOperations
from auth_guide.management_api import create_management_application, create_management_server
from auth_guide.secrets import MissingSecretError, PlatformSecretProvider, SecretReference
from auth_guide.tls import LocalCertificateAuthority

TEST_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$MDEyMzQ1Njc4OWFiY2RlZg$PjSoTrIgSEYn0GfJ1m5dwCJmQtOaMjFFTIwHP6GJwrs"


@dataclass
class MemoryKeyring:
    """A keyring double for provider-owned TLS test material."""

    values: dict[tuple[str, str], str] = field(default_factory=dict)

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        del self.values[(service_name, username)]


class FailingKeyring(MemoryKeyring):
    """Reject secret creation to exercise the first bootstrap failure stage."""

    def set_password(self, service_name: str, username: str, password: str) -> None:
        del service_name, username, password
        raise RuntimeError("keyring write failed")


class BootstrapStore:
    """Exercise the management API's lifecycle contract with ordinary test persistence."""

    def __init__(self, failure_stage: str | None = None) -> None:
        self.failure_stage = failure_stage
        self.rollback_calls = 0
        self.initialised = False

    async def initialise(self) -> None:
        """Simulate the account-store initialisation boundary."""
        if self.failure_stage == "initialise":
            raise AccountStoreError("initialisation failed")
        if self.initialised:
            raise AccountStoreError("database already exists")
        self.initialised = True

    async def reset_password(self, account: AccountRecord, _: str) -> None:
        """Persist the observable bootstrap password-change state."""
        if self.failure_stage == "password":
            raise RuntimeError("password persistence failed")
        account.must_change_password = True
        await account.save(update_fields=["must_change_password"])

    async def set_password(self, account: AccountRecord, _: str) -> None:
        """Persist the observable normal password-replacement state."""
        account.must_change_password = False
        await account.save(update_fields=["must_change_password"])

    async def create_account(self, account: AccountRecord, _: str) -> None:
        """Persist a provisioned account only after its initial password succeeds."""
        if self.failure_stage == "password":
            raise RuntimeError("password persistence failed")
        account.password_hash = TEST_PASSWORD_HASH
        account.must_change_password = True
        await account.save()

    async def rollback_initialisation(self) -> None:
        """Represent removal of state created during this request only."""
        self.rollback_calls += 1
        self.initialised = False
        await AccountTokenRecord.all().delete()
        await AccountRecord.including_inactive().delete()


@pytest.fixture
async def management_database():
    """Provide ephemeral ordinary persistence for API behaviour, not encryption tests."""
    await Tortoise.init(db_url="sqlite://:memory:", modules={"accounts": ["auth_guide.accounts.models"]})
    await Tortoise.generate_schemas()
    try:
        yield
    finally:
        await Tortoise.close_connections()


async def create_authenticated_bearer(*scopes: Grant) -> str:
    """Create an active account and return one of its raw API bearers."""
    account = await AccountRecord.create(
        email="admin@example.com",
        grants=[Grant.GUIDE_ADMIN, Grant.ACCOUNTS_READ, Grant.ACCOUNTS_MANAGE, Grant.TOKENS_MANAGE],
        password_hash=TEST_PASSWORD_HASH,
    )
    issued = await generate_account_token()
    await AccountTokenRecord.create(
        account=account,
        label="test",
        verifier=issued.verifier,
        scopes=list(scopes),
    )
    return issued.raw_value


@pytest.mark.anyio
async def test_management_application_publishes_openapi_without_interactive_documentation() -> None:
    """The typed API contract remains available without serving Swagger or ReDoc."""
    application = create_management_application()
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        openapi_response = await client.get("/openapi.json")
        swagger_response = await client.get("/docs")
        redoc_response = await client.get("/redoc")

    assert openapi_response.status_code == 200
    assert openapi_response.json()["openapi"]
    assert "/v1/authenticate" in openapi_response.json()["paths"]
    assert "/v1/setup" in openapi_response.json()["paths"]
    setup_parameters = openapi_response.json()["paths"]["/v1/setup"]["post"]["parameters"]
    assert {parameter["name"] for parameter in setup_parameters} == {"remove_orphan_key"}
    assert setup_parameters[0]["in"] == "query"
    assert setup_parameters[0]["schema"]["default"] is False
    assert "/v1/accounts" in openapi_response.json()["paths"]
    assert "/v1/tokens" in openapi_response.json()["paths"]
    assert swagger_response.status_code == 404
    assert redoc_response.status_code == 404


@pytest.mark.anyio
async def test_management_server_serves_only_trusted_https(tmp_path) -> None:
    """Every management operation works through trusted HTTPS, never plaintext."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    async with PlatformSecretProvider("management-api-test", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(AsyncPath(tmp_path) / "tls", secrets) as authority:
            await authority.initialise()
            store = AccountStore(AsyncPath(tmp_path) / "accounts", secrets)
            server = await create_management_server(
                create_management_application(store), authority, host="127.0.0.1", port=port
            )
            serving = asyncio.create_task(server.serve(sockets=[listener]))
            while not server.started:
                await asyncio.sleep(0)
            try:
                trusted_context = ssl.create_default_context(cadata=await authority.get_root_certificate())
                async with httpx.AsyncClient(verify=trusted_context) as client:
                    base_url = f"https://localhost:{port}"
                    openapi = await client.get(f"{base_url}/openapi.json")
                    setup = await client.post(f"{base_url}/v1/setup", json={"email": "admin@example.com"})
                    bearer = setup.json()["token"]
                    headers = {"Authorization": f"Bearer {bearer}"}

                    authenticated = await client.post(f"{base_url}/v1/authenticate", headers=headers)
                    own_account = await client.get(f"{base_url}/v1/accounts/me", headers=headers)
                    own_update = await client.patch(
                        f"{base_url}/v1/accounts/me", headers=headers, json={"full_name": "Admin User"}
                    )
                    own_password = await client.post(
                        f"{base_url}/v1/accounts/me/password", headers=headers, json={"password": "new password"}
                    )
                    created = await client.post(
                        f"{base_url}/v1/accounts",
                        headers=headers,
                        json={
                            "email": "member@example.com",
                            "grants": ["accounts:read"],
                            "password": "initial password",
                        },
                    )
                    account_id = created.json()["id"]
                    listed = await client.get(f"{base_url}/v1/accounts", headers=headers)
                    read = await client.get(f"{base_url}/v1/accounts/{account_id}", headers=headers)
                    updated = await client.patch(
                        f"{base_url}/v1/accounts/{account_id}",
                        headers=headers,
                        json={"grants": ["accounts:read"]},
                    )
                    reset = await client.post(
                        f"{base_url}/v1/accounts/{account_id}/password",
                        headers=headers,
                        json={"password": "new password"},
                    )
                    own_token = await client.post(
                        f"{base_url}/v1/tokens", headers=headers, json={"label": "laptop", "scopes": ["accounts:read"]}
                    )
                    delegated_token = await client.post(
                        f"{base_url}/v1/tokens",
                        headers=headers,
                        json={
                            "account_id": account_id,
                            "label": "member",
                            "scopes": ["accounts:read"],
                        },
                    )
                    token_id = delegated_token.json()["id"]
                    own_tokens = await client.get(f"{base_url}/v1/tokens", headers=headers)
                    delegated_tokens = await client.get(
                        f"{base_url}/v1/tokens?account_id={account_id}", headers=headers
                    )
                    relabelled = await client.patch(
                        f"{base_url}/v1/tokens/{token_id}", headers=headers, json={"label": "member-laptop"}
                    )
                    revoked = await client.delete(f"{base_url}/v1/tokens/{token_id}", headers=headers)
                    deleted = await client.delete(f"{base_url}/v1/accounts/{account_id}", headers=headers)
                    closed = await client.post(f"{base_url}/v1/accounts/me/close", headers=headers)
                    rejected = await client.post(f"{base_url}/v1/authenticate", headers=headers)

                assert openapi.status_code == 200
                assert setup.status_code == 201
                assert authenticated.status_code == 200
                assert own_account.status_code == 200
                assert own_update.status_code == 200
                assert own_password.status_code == 200
                assert created.status_code == 201
                assert listed.status_code == 200
                assert read.status_code == 200
                assert updated.status_code == 200
                assert reset.status_code == 200
                assert own_token.status_code == 201
                assert delegated_token.status_code == 201
                assert own_tokens.status_code == 200
                assert delegated_tokens.status_code == 200
                assert relabelled.status_code == 200
                assert revoked.status_code == 204
                assert deleted.status_code == 204
                assert closed.status_code == 200
                assert rejected.status_code == 401

                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"GET /openapi.json HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer.drain()
                plaintext_response = await reader.read(128)
                writer.close()
                await writer.wait_closed()
                assert not plaintext_response.startswith(b"HTTP/")
            finally:
                server.should_exit = True
                await serving
                await store.aclose()


@pytest.mark.anyio
async def test_valid_bearer_authenticates_for_guide_without_management_grants(management_database) -> None:
    """Guide receives only its recognised administrator scope from a valid bearer."""
    bearer = await create_authenticated_bearer()
    application = create_management_application()
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post("/v1/authenticate", headers={"Authorization": f"Bearer {bearer}"})

    assert response.status_code == 200
    assert response.json()["scopes"] == ["admin"]


@pytest.mark.anyio
async def test_token_lifecycle_returns_raw_value_once_and_hides_credential_material(management_database) -> None:
    """Account tokens are created, listed, and represented without stored secrets."""
    bearer = await create_authenticated_bearer(Grant.ACCOUNTS_READ)
    application = create_management_application()
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        creation = await client.post(
            "/v1/tokens",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"label": "laptop", "scopes": ["accounts:read"]},
        )
        listed = await client.get("/v1/tokens", headers={"Authorization": f"Bearer {bearer}"})
        token_id = creation.json()["id"]
        relabelled = await client.patch(
            f"/v1/tokens/{token_id}",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"label": "work-laptop"},
        )
        revoked = await client.delete(f"/v1/tokens/{token_id}", headers={"Authorization": f"Bearer {bearer}"})
        rejected_scope = await client.post(
            "/v1/tokens",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"label": "forbidden", "scopes": ["tokens:manage"]},
        )

    assert creation.status_code == 201
    created = creation.json()
    assert created["token"].startswith("agt_")
    assert "verifier" not in created
    assert "token" not in listed.json()[0]
    assert all("verifier" not in token for token in listed.json())
    assert relabelled.status_code == 200
    assert relabelled.json()["label"] == "work-laptop"
    assert revoked.status_code == 204
    assert rejected_scope.status_code == 403


@pytest.mark.anyio
async def test_token_without_management_scope_cannot_create_an_account(management_database) -> None:
    """A bearer lacking accounts:manage cannot perform a privileged mutation."""
    bearer = await create_authenticated_bearer()
    application = create_management_application()
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post(
            "/v1/accounts",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "member@example.com", "grants": [], "password": "initial password"},
        )

    assert response.status_code == 403


@pytest.mark.anyio
async def test_management_routes_reject_client_database_configuration(management_database) -> None:
    """Clients cannot smuggle database paths or credentials through API input."""
    application = create_management_application()
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post(
            "/v1/setup",
            json={"email": "admin@example.com", "database_path": "/tmp/client.sqlite3"},
        )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_account_manager_can_create_an_account_with_an_initial_password(management_database) -> None:
    """An account manager must provide an initial non-empty password."""
    bearer = await create_authenticated_bearer(Grant.ACCOUNTS_MANAGE)
    application = create_management_application(cast(AccountStore, BootstrapStore()))
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post(
            "/v1/accounts",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "member@example.com", "grants": [], "password": "initial password"},
        )
        missing_password = await client.post(
            "/v1/accounts",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "no-password@example.com", "grants": []},
        )
        empty_password = await client.post(
            "/v1/accounts",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "empty-password@example.com", "grants": [], "password": ""},
        )
        short_password = await client.post(
            "/v1/accounts",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "short-password@example.com", "grants": [], "password": "too short"},
        )

    assert response.status_code == 201
    assert response.json()["email"] == "member@example.com"
    assert response.json()["grants"] == []
    assert missing_password.status_code == 422
    assert empty_password.status_code == 422
    assert short_password.status_code == 422


@pytest.mark.anyio
async def test_invalid_account_emails_are_rejected_as_client_errors(management_database) -> None:
    """Self-service updates do not distinguish invalid and registered identifiers."""
    bearer = await create_authenticated_bearer(Grant.ACCOUNTS_MANAGE)
    await AccountRecord.create(email="member@example.com", grants=[], password_hash=TEST_PASSWORD_HASH)
    application = create_management_application(cast(AccountStore, BootstrapStore()))
    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        created = await client.post(
            "/v1/accounts",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "not-an-email", "grants": [], "password": "initial password"},
        )
        updated = await client.patch(
            "/v1/accounts/me",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "not-an-email"},
        )
        duplicate = await client.patch(
            "/v1/accounts/me",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "member@example.com"},
        )

    assert created.status_code == 422
    assert updated.status_code == 422
    assert duplicate.status_code == 422
    assert duplicate.json() == updated.json()


@pytest.mark.anyio
async def test_invalid_account_grants_are_rejected_as_client_errors(management_database) -> None:
    """Duplicate grant sets return client errors for account creation and replacement."""
    bearer = await create_authenticated_bearer(Grant.ACCOUNTS_MANAGE)
    target = await AccountRecord.create(email="member@example.com", grants=[], password_hash=TEST_PASSWORD_HASH)
    application = create_management_application(cast(AccountStore, BootstrapStore()))
    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        created = await client.post(
            "/v1/accounts",
            headers={"Authorization": f"Bearer {bearer}"},
            json={
                "email": "duplicate@example.com",
                "grants": ["accounts:read", "accounts:read"],
                "password": "initial password",
            },
        )
        updated = await client.patch(
            f"/v1/accounts/{target.id}",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"grants": ["accounts:read", "accounts:read"]},
        )

    assert created.status_code == 422
    assert updated.status_code == 422


@pytest.mark.anyio
async def test_failed_initial_password_persistence_does_not_create_an_account(management_database) -> None:
    """A failed initial password prevents the account record being persisted."""
    bearer = await create_authenticated_bearer(Grant.ACCOUNTS_MANAGE)
    application = create_management_application(cast(AccountStore, BootstrapStore("password")))
    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post(
            "/v1/accounts",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"email": "member@example.com", "grants": [], "password": "initial password"},
        )

    assert response.status_code == 500
    assert await AccountRecord.including_inactive().get_or_none(email="member@example.com") is None


@pytest.mark.anyio
async def test_account_can_update_its_profile_and_close_itself(management_database) -> None:
    """Self-service profile changes are permitted until the account is closed."""
    bearer = await create_authenticated_bearer()
    account = await AccountRecord.get(email="admin@example.com")
    account.must_change_password = True
    await account.save(update_fields=["must_change_password"])
    application = create_management_application(cast(AccountStore, BootstrapStore()))
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        updated = await client.patch(
            "/v1/accounts/me",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"full_name": "Ada Lovelace"},
        )
        password = await client.post(
            "/v1/accounts/me/password",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"password": "replacement password"},
        )
        closed = await client.post("/v1/accounts/me/close", headers={"Authorization": f"Bearer {bearer}"})
        rejected = await client.post("/v1/authenticate", headers={"Authorization": f"Bearer {bearer}"})

    assert updated.status_code == 200
    assert updated.json()["full_name"] == "Ada Lovelace"
    assert password.json()["must_change_password"] is False
    assert closed.status_code == 200
    assert rejected.status_code == 401


@pytest.mark.anyio
async def test_password_routes_reject_passwords_shorter_than_twelve_characters(management_database) -> None:
    """Self-service replacement and managed reset share the minimum password length."""
    bearer = await create_authenticated_bearer(Grant.ACCOUNTS_MANAGE)
    target = await AccountRecord.create(email="member@example.com", grants=[], password_hash=TEST_PASSWORD_HASH)
    application = create_management_application(cast(AccountStore, BootstrapStore()))
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        own = await client.post(
            "/v1/accounts/me/password",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"password": "too short"},
        )
        reset = await client.post(
            f"/v1/accounts/{target.id}/password",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"password": "too short"},
        )

    assert own.status_code == 422
    assert reset.status_code == 422


@pytest.mark.anyio
async def test_account_manager_can_read_update_reset_and_delete_accounts(management_database) -> None:
    """Each privileged account operation is available only through the HTTPS API."""
    bearer = await create_authenticated_bearer(Grant.ACCOUNTS_READ, Grant.ACCOUNTS_MANAGE)
    target = await AccountRecord.create(
        email="member@example.com",
        grants=[Grant.ACCOUNTS_READ],
        password_hash=TEST_PASSWORD_HASH,
        expires_at=datetime.now(timezone.utc),
        must_change_password=False,
    )
    store = BootstrapStore()
    application = create_management_application(cast(AccountStore, store))
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        listed = await client.get("/v1/accounts", headers={"Authorization": f"Bearer {bearer}"})
        read = await client.get(f"/v1/accounts/{target.id}", headers={"Authorization": f"Bearer {bearer}"})
        updated = await client.patch(
            f"/v1/accounts/{target.id}",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"grants": ["tokens:manage"], "reactivate": True},
        )
        reset = await client.post(
            f"/v1/accounts/{target.id}/password",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"password": "new password"},
        )
        deleted = await client.delete(f"/v1/accounts/{target.id}", headers={"Authorization": f"Bearer {bearer}"})

    assert listed.status_code == 200
    assert read.status_code == 200
    assert updated.json()["grants"] == ["tokens:manage"]
    assert updated.json()["expires_at"] is None
    assert reset.json()["must_change_password"] is True
    assert deleted.status_code == 204
    assert await AccountRecord.including_inactive().get_or_none(id=target.id) is None


@pytest.mark.anyio
async def test_token_manager_can_issue_and_revoke_another_accounts_token(management_database) -> None:
    """Delegated token issuance is limited by both the caller and recipient grants."""
    bearer = await create_authenticated_bearer(Grant.TOKENS_MANAGE, Grant.ACCOUNTS_READ)
    target = await AccountRecord.create(
        email="member@example.com", grants=[Grant.ACCOUNTS_READ], password_hash=TEST_PASSWORD_HASH
    )
    application = create_management_application()
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        issued = await client.post(
            "/v1/tokens",
            headers={"Authorization": f"Bearer {bearer}"},
            json={"account_id": str(target.id), "label": "member", "scopes": ["accounts:read"]},
        )
        token_id = issued.json()["id"]
        listed = await client.get(f"/v1/tokens?account_id={target.id}", headers={"Authorization": f"Bearer {bearer}"})
        revoked = await client.delete(f"/v1/tokens/{token_id}", headers={"Authorization": f"Bearer {bearer}"})

    assert issued.status_code == 201
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == token_id
    assert revoked.status_code == 204


@pytest.mark.anyio
async def test_setup_requires_an_explicit_account_store_runtime() -> None:
    """The unauthenticated setup route cannot create state without its runtime."""
    application = create_management_application()
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post("/v1/setup", json={"email": "admin@example.com"})

    assert response.status_code == 503


@pytest.mark.anyio
async def test_setup_creates_the_initial_account_and_returns_credentials_once(management_database) -> None:
    """Setup returns its generated password/token but persists only their safe state."""
    store = BootstrapStore()
    application = create_management_application(cast(AccountStore, store))
    transport = httpx.ASGITransport(app=application)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post("/v1/setup", json={"email": "admin@example.com"})

    assert response.status_code == 201
    result = response.json()
    assert len(result["password"]) == 12
    assert result["token"].startswith("agt_")
    assert result["account"]["must_change_password"] is True
    assert await AccountRecord.all().count() == 1
    assert await AccountTokenRecord.all().count() == 1
    assert store.rollback_calls == 0


@pytest.mark.anyio
async def test_setup_runs_the_real_account_store_initialisation_and_native_migration(tmp_path) -> None:
    """Bootstrap creates the encrypted store through its actual native migration lifecycle."""
    keyring = MemoryKeyring()
    async with PlatformSecretProvider("real-bootstrap-test", keyring) as secrets:
        store = AccountStore(tmp_path, secrets)
        application = create_management_application(store)
        transport = httpx.ASGITransport(app=application)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
                response = await client.post("/v1/setup", json={"email": "admin@example.com"})

            assert response.status_code == 201
            assert await (AsyncPath(tmp_path) / DATABASE_FILENAME).exists()
            assert await secrets.resolve(SecretReference("auth-guide-database-key"))
            account = await AccountRecord.get(email="admin@example.com")
            assert account.must_change_password
            assert await AccountTokenRecord.all().count() == 1
        finally:
            await store.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("database_exists", "key_exists", "remove_orphan_key", "expected_status"),
    [
        (False, True, False, 409),
        (False, True, True, 201),
        (True, True, True, 409),
        (True, False, True, 409),
        (False, False, True, 409),
    ],
)
async def test_setup_recovers_only_an_explicit_orphaned_database_key(
    tmp_path,
    database_exists: bool,
    key_exists: bool,
    remove_orphan_key: bool,
    expected_status: int,
) -> None:
    """Setup removes a key only for the explicitly selected orphaned-key state."""
    database_path = AsyncPath(tmp_path) / DATABASE_FILENAME
    orphaned_key = "orphaned-database-key"
    if database_exists:
        await database_path.write_bytes(b"pre-existing database")

    async with PlatformSecretProvider("orphan-key-recovery-test", MemoryKeyring()) as secrets:
        if key_exists:
            await secrets.store(DATABASE_KEY_REFERENCE, orphaned_key)
        store = AccountStore(tmp_path, secrets)
        application = create_management_application(store)
        transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)
        try:
            query = "?remove_orphan_key=true" if remove_orphan_key else ""
            async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
                response = await client.post(f"/v1/setup{query}", json={"email": "admin@example.com"})

            assert response.status_code == expected_status
            assert orphaned_key not in response.text
            if expected_status == 201:
                assert await database_path.exists()
                assert await secrets.resolve(DATABASE_KEY_REFERENCE) != orphaned_key
            else:
                assert await database_path.exists() is database_exists
                if key_exists:
                    assert await secrets.resolve(DATABASE_KEY_REFERENCE) == orphaned_key
                else:
                    with pytest.raises(MissingSecretError):
                        await secrets.resolve(DATABASE_KEY_REFERENCE)
        finally:
            await store.aclose()


@pytest.mark.anyio
async def test_setup_recovers_an_orphaned_key_after_store_readiness_start(tmp_path) -> None:
    """Explicit recovery reuses a store started for no-database readiness."""
    orphaned_key = b64encode(b"x" * 32).decode("ascii")
    async with PlatformSecretProvider("orphan-key-readiness-test", MemoryKeyring()) as secrets:
        await secrets.store(DATABASE_KEY_REFERENCE, orphaned_key)
        store = AccountStore(tmp_path, secrets)
        await store.start()
        application = create_management_application(store)
        transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
                response = await client.post("/v1/setup?remove_orphan_key=true", json={"email": "admin@example.com"})

            assert response.status_code == 201
            assert await (AsyncPath(tmp_path) / DATABASE_FILENAME).exists()
            assert await secrets.resolve(DATABASE_KEY_REFERENCE) != orphaned_key
        finally:
            await store.aclose()


@pytest.mark.anyio
async def test_real_setup_removes_partial_state_when_key_creation_fails(tmp_path) -> None:
    """A failed platform-key write leaves no database or usable database key."""
    async with PlatformSecretProvider("real-bootstrap-test", FailingKeyring()) as secrets:
        store = AccountStore(tmp_path, secrets)
        application = create_management_application(store)
        transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
                response = await client.post("/v1/setup", json={"email": "admin@example.com"})

            assert response.status_code == 500
            assert not await (AsyncPath(tmp_path) / DATABASE_FILENAME).exists()
            with pytest.raises(MissingSecretError):
                await secrets.resolve(DATABASE_KEY_REFERENCE)
        finally:
            await store.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize("failure_stage", ["migration", "account", "password", "token"])
async def test_real_setup_rolls_back_each_post_key_failure_stage(
    tmp_path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    """Failures after creating the key remove both actual encrypted-store resources."""

    async def fail(*_: object, **__: object) -> None:
        raise RuntimeError(f"{failure_stage} failed")

    if failure_stage == "migration":
        monkeypatch.setattr(accounts_module, "migrate", fail)
    elif failure_stage == "account":
        monkeypatch.setattr(AccountRecord, "save", fail)
    elif failure_stage == "password":
        monkeypatch.setattr(PasswordOperations, "hash", fail)
    else:
        monkeypatch.setattr(AccountTokenRecord, "create", fail)

    keyring = MemoryKeyring()
    async with PlatformSecretProvider("real-bootstrap-test", keyring) as secrets:
        store = AccountStore(tmp_path, secrets)
        application = create_management_application(store)
        transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)
        try:
            async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
                response = await client.post("/v1/setup", json={"email": "admin@example.com"})

            assert response.status_code == 500
            assert not await (AsyncPath(tmp_path) / DATABASE_FILENAME).exists()
            with pytest.raises(MissingSecretError):
                await secrets.resolve(DATABASE_KEY_REFERENCE)
        finally:
            await store.aclose()


@pytest.mark.anyio
async def test_concurrent_setup_requests_leave_one_initial_administrator(management_database) -> None:
    """Competing setup requests cannot each create an initial administrator."""
    store = BootstrapStore()
    application = create_management_application(cast(AccountStore, store))
    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        first, second = await asyncio.gather(
            client.post("/v1/setup", json={"email": "admin@example.com"}),
            client.post("/v1/setup", json={"email": "admin@example.com"}),
        )

    assert sorted((first.status_code, second.status_code)) == [201, 409]
    assert await AccountRecord.all().count() == 1
    assert await AccountTokenRecord.all().count() == 1


@pytest.mark.anyio
@pytest.mark.parametrize("failure_stage", ["initialise", "password"])
async def test_setup_failure_does_not_leave_account_or_token_state(management_database, failure_stage: str) -> None:
    """A setup failure either creates nothing or rolls back request-created state."""
    store = BootstrapStore(failure_stage)
    application = create_management_application(cast(AccountStore, store))
    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post("/v1/setup", json={"email": "admin@example.com"})

    assert response.status_code in {409, 500}
    assert await AccountRecord.all().count() == 0
    assert await AccountTokenRecord.all().count() == 0
    assert store.rollback_calls == (0 if failure_stage == "initialise" else 1)


@pytest.mark.anyio
@pytest.mark.parametrize("failed_model", [AccountRecord, AccountTokenRecord])
async def test_setup_rolls_back_when_account_or_token_persistence_fails(
    management_database, monkeypatch: pytest.MonkeyPatch, failed_model: type[AccountRecord] | type[AccountTokenRecord]
) -> None:
    """Model persistence failures after initialisation remove request-created state."""
    store = BootstrapStore()

    async def fail_persistence(*_: object, **__: object) -> None:
        raise RuntimeError("persistence failed")

    monkeypatch.setattr(failed_model, "create" if failed_model is AccountTokenRecord else "save", fail_persistence)
    application = create_management_application(cast(AccountStore, store))
    transport = httpx.ASGITransport(app=application, raise_app_exceptions=False)

    async with httpx.AsyncClient(transport=transport, base_url="https://auth-guide.test") as client:
        response = await client.post("/v1/setup", json={"email": "admin@example.com"})

    assert response.status_code == 500
    assert await AccountRecord.all().count() == 0
    assert await AccountTokenRecord.all().count() == 0
    assert store.rollback_calls == 1
