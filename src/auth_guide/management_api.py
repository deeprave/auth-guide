"""HTTPS-only management API application factory."""

import asyncio
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from tortoise.exceptions import IntegrityError
from uvicorn import Config, Server

from auth_guide.accounts import (
    AccountRecord,
    AccountStore,
    AccountStoreError,
    AccountTokenRecord,
    Grant,
    generate_account_token,
    resolve_account_token,
)
from auth_guide.accounts.models import normalise_account_email
from auth_guide.tls import LocalCertificateAuthority


class AccountResponse(BaseModel):
    """Non-secret account metadata returned by the management API."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    grants: list[str]
    created_at: datetime
    expires_at: datetime | None
    full_name: str | None
    must_change_password: bool


class TokenResponse(BaseModel):
    """Non-secret metadata for a single account token."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    account_id: UUID
    label: str
    scopes: list[str]
    created_at: datetime


class RequestModel(BaseModel):
    """Reject fields outside the provider's public management contract."""

    model_config = ConfigDict(extra="forbid")


class TokenCreationRequest(RequestModel):
    """Request body for a new self-service or delegated account token."""

    label: str = Field(min_length=1)
    scopes: list[Grant]
    account_id: UUID | None = None


class TokenCreationResponse(TokenResponse):
    """A newly issued token, including its once-only raw bearer value."""

    token: str


class SetupRequest(RequestModel):
    """The first administrator identity accepted during initial setup."""

    email: str


class SetupResponse(BaseModel):
    """Once-only credentials returned from a successful initial setup."""

    account: AccountResponse
    password: str
    token: str


class TokenLabelUpdate(RequestModel):
    """The only mutable account-token property."""

    label: str = Field(min_length=1)


class AccountCreationRequest(RequestModel):
    """Privileged account creation input."""

    email: str
    grants: list[Grant]
    full_name: str | None = None
    password: str = Field(min_length=12)


class AccountSelfUpdate(RequestModel):
    """Fields an active account may update on itself."""

    email: str | None = None
    full_name: str | None = None


class AccountManagementUpdate(RequestModel):
    """Fields an account manager may alter on another account."""

    grants: list[Grant] | None = None
    reactivate: bool | None = None


class PasswordUpdate(RequestModel):
    """A password replacement submitted through the HTTPS control plane."""

    password: str = Field(min_length=12)


class GuideAuthenticationResponse(BaseModel):
    """The limited provider decision consumed by the future Guide adapter."""

    account_id: UUID
    scopes: list[str]


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """An active account authenticated by one of its presented tokens."""

    account: AccountRecord
    token: AccountTokenRecord


bearer_scheme = HTTPBearer(auto_error=False)


async def generate_initial_password() -> str:
    """Generate the required 12-character printable-ASCII bootstrap password."""
    printable_ascii = "".join(chr(value) for value in range(33, 127))
    return "".join(secrets.choice(printable_ascii) for _ in range(12))


def token_response(token: AccountTokenRecord) -> TokenResponse:
    """Return the non-secret token representation for an eager-loaded token."""
    return TokenResponse(
        id=token.id,
        account_id=token.account.id,
        label=token.label,
        scopes=token.scopes,
        created_at=token.created_at,
    )


def create_management_application(account_store: AccountStore | None = None) -> FastAPI:
    """Create the provider's versioned management API application."""
    application = FastAPI(
        title="auth-guide management API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    setup_lock = asyncio.Lock()

    async def require_principal(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    ) -> AuthenticatedPrincipal:
        """Resolve the request's bearer to a current active account token."""
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer authentication is required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = await resolve_account_token(credentials.credentials)
        if token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer authentication is invalid",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return AuthenticatedPrincipal(account=token.account, token=token)

    async def require_store() -> AccountStore:
        """Require the explicit, already-started account-store runtime."""
        if account_store is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Account storage is unavailable",
            )
        return account_store

    async def require_account_grant(
        grant: Grant,
        principal: AuthenticatedPrincipal,
    ) -> AuthenticatedPrincipal:
        """Require a capability on both the account and its presented token."""
        if grant not in principal.token.scopes or not principal.account.has_grant(grant):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token does not permit this operation")
        return principal

    async def require_accounts_read(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> AuthenticatedPrincipal:
        """Require account-read authority for an all-account operation."""
        return await require_account_grant(Grant.ACCOUNTS_READ, principal)

    async def require_accounts_manage(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> AuthenticatedPrincipal:
        """Require account-management authority for a privileged mutation."""
        return await require_account_grant(Grant.ACCOUNTS_MANAGE, principal)

    async def perform_setup(request: SetupRequest, *, remove_orphan_key: bool) -> SetupResponse:
        """Create the first administrator only through a fresh account store."""
        store = await require_store()
        try:
            email_values = await normalise_account_email(request.email)
        except ValueError as error:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from error
        initialised = False
        try:
            if remove_orphan_key:
                await store.remove_orphan_database_key()
            await store.initialise()
            initialised = True
            password = await generate_initial_password()
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
        except AccountStoreError as error:
            if initialised:
                await store.rollback_initialisation()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
        except BaseException:
            if initialised:
                await store.rollback_initialisation()
            raise
        return SetupResponse(
            account=AccountResponse.model_validate(account),
            password=password,
            token=issued_token.raw_value,
        )

    @application.post("/v1/setup", response_model=SetupResponse, status_code=status.HTTP_201_CREATED)
    async def setup_first_administrator(
        request: SetupRequest,
        remove_orphan_key: Annotated[bool, Query()] = False,
    ) -> SetupResponse:
        """Serialise competing initial setup requests within this API process."""
        async with setup_lock:
            return await perform_setup(request, remove_orphan_key=remove_orphan_key)

    @application.post("/v1/authenticate", response_model=GuideAuthenticationResponse)
    async def authenticate_for_guide(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> GuideAuthenticationResponse:
        """Return the minimal Guide-facing decision for one valid bearer."""
        scopes = ["admin"] if principal.account.has_grant(Grant.GUIDE_ADMIN) else []
        return GuideAuthenticationResponse(account_id=principal.account.id, scopes=scopes)

    @application.get("/v1/accounts/me", response_model=AccountResponse)
    async def read_own_account(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> AccountRecord:
        """Return the caller's complete account record."""
        return principal.account

    @application.patch("/v1/accounts/me", response_model=AccountResponse)
    async def update_own_account(
        update: AccountSelfUpdate,
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> AccountRecord:
        """Update only the caller's own profile metadata."""
        account = principal.account
        update_fields: list[str] = []
        if "email" in update.model_fields_set:
            account.email = update.email or ""
            update_fields.append("email")
        if "full_name" in update.model_fields_set:
            account.update_from_dict({"full_name": update.full_name})
            update_fields.append("full_name")
        if not update_fields:
            return account
        try:
            await account.save(update_fields=update_fields)
        except (IntegrityError, ValueError) as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Account profile update is invalid",
            ) from error
        return account

    @application.post("/v1/accounts/me/password", response_model=AccountResponse)
    async def replace_own_password(
        update: PasswordUpdate,
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
        store: Annotated[AccountStore, Depends(require_store)],
    ) -> AccountRecord:
        """Replace the caller's password and clear its change requirement."""
        await store.set_password(principal.account, update.password)
        return principal.account

    @application.post("/v1/accounts/me/close", response_model=AccountResponse)
    async def close_own_account(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> AccountRecord:
        """Close the caller's account by making it immediately inactive."""
        principal.account.expires_at = datetime.now(timezone.utc)
        await principal.account.save(update_fields=["expires_at"])
        return principal.account

    @application.get("/v1/accounts", response_model=list[AccountResponse])
    async def list_accounts(
        _: Annotated[AuthenticatedPrincipal, Depends(require_accounts_read)],
    ) -> list[AccountRecord]:
        """List every account, including inactive records, for account readers."""
        return await AccountRecord.including_inactive().order_by("email_comparison")

    @application.get("/v1/accounts/{account_id}", response_model=AccountResponse)
    async def read_account(
        account_id: UUID,
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> AccountRecord:
        """Read own account or any account when the token permits account reads."""
        if account_id == principal.account.id:
            return principal.account
        await require_account_grant(Grant.ACCOUNTS_READ, principal)
        account = await AccountRecord.including_inactive().get_or_none(id=account_id)
        if account is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account does not exist")
        return account

    @application.post("/v1/accounts", response_model=AccountResponse, status_code=status.HTTP_201_CREATED)
    async def create_account(
        request: AccountCreationRequest,
        _: Annotated[AuthenticatedPrincipal, Depends(require_accounts_manage)],
        store: Annotated[AccountStore, Depends(require_store)],
    ) -> AccountRecord:
        """Create a new account with its complete grant set and initial password."""
        account = AccountRecord(email=request.email, grants=request.grants, full_name=request.full_name)
        try:
            await store.create_account(account, request.password)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Account values are invalid",
            ) from error
        except IntegrityError as error:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account email already exists") from error
        return account

    @application.patch("/v1/accounts/{account_id}", response_model=AccountResponse)
    async def manage_account(
        account_id: UUID,
        update: AccountManagementUpdate,
        _: Annotated[AuthenticatedPrincipal, Depends(require_accounts_manage)],
    ) -> AccountRecord:
        """Replace grants or reactivate another account without editing its profile."""
        account = await AccountRecord.including_inactive().get_or_none(id=account_id)
        if account is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account does not exist")
        update_fields: list[str] = []
        if "grants" in update.model_fields_set:
            account.grants = update.grants or []
            update_fields.append("grants")
        if update.reactivate is True:
            account.expires_at = None
            update_fields.append("expires_at")
        if update_fields:
            try:
                await account.save(update_fields=update_fields)
            except ValueError as error:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Account values are invalid",
                ) from error
        return account

    @application.post("/v1/accounts/{account_id}/password", response_model=AccountResponse)
    async def reset_account_password(
        account_id: UUID,
        update: PasswordUpdate,
        _: Annotated[AuthenticatedPrincipal, Depends(require_accounts_manage)],
        store: Annotated[AccountStore, Depends(require_store)],
    ) -> AccountRecord:
        """Reset another account's password and require it to be changed."""
        account = await AccountRecord.including_inactive().get_or_none(id=account_id)
        if account is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account does not exist")
        await store.reset_password(account, update.password)
        return account

    @application.delete("/v1/accounts/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_account(
        account_id: UUID,
        _: Annotated[AuthenticatedPrincipal, Depends(require_accounts_manage)],
    ) -> None:
        """Permanently remove an account under administrator authority."""
        account = await AccountRecord.including_inactive().get_or_none(id=account_id)
        if account is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account does not exist")
        await account.delete()

    @application.get("/v1/tokens", response_model=list[TokenResponse])
    async def list_tokens(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
        account_id: Annotated[UUID | None, Query()] = None,
    ) -> list[TokenResponse]:
        """List own token metadata, or another account's with token management."""
        target_account_id = principal.account.id if account_id is None else account_id
        if target_account_id != principal.account.id:
            await require_account_grant(Grant.TOKENS_MANAGE, principal)
        tokens = (
            await AccountTokenRecord.filter(account__id=target_account_id)
            .select_related("account")
            .order_by("created_at")
        )
        return [token_response(token) for token in tokens]

    @application.post("/v1/tokens", response_model=TokenCreationResponse, status_code=status.HTTP_201_CREATED)
    async def create_token(
        request: TokenCreationRequest,
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> TokenCreationResponse:
        """Create a scope-limited token for the caller or a managed account."""
        target_account_id = principal.account.id if request.account_id is None else request.account_id
        if target_account_id == principal.account.id:
            account = principal.account
        else:
            await require_account_grant(Grant.TOKENS_MANAGE, principal)
            account = await AccountRecord.get_or_none(id=target_account_id)
            if account is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active account does not exist")
        requested_scopes = {str(scope) for scope in request.scopes}
        if not requested_scopes.issubset(principal.token.scopes) or not requested_scopes.issubset(account.grants):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token scopes exceed delegated authority")
        issued_token = await generate_account_token()
        token = await AccountTokenRecord.create(
            account=account,
            label=request.label,
            verifier=issued_token.verifier,
            scopes=sorted(requested_scopes),
        )
        return TokenCreationResponse(**token_response(token).model_dump(), token=issued_token.raw_value)

    @application.patch("/v1/tokens/{token_id}", response_model=TokenResponse)
    async def relabel_token(
        token_id: UUID,
        update: TokenLabelUpdate,
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> TokenResponse:
        """Relabel an owned token or one visible through token management."""
        token = await AccountTokenRecord.all().select_related("account").get_or_none(id=token_id)
        if token is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token does not exist")
        if token.account.id != principal.account.id:
            await require_account_grant(Grant.TOKENS_MANAGE, principal)
        token.label = update.label
        await token.save(update_fields=["label"])
        return token_response(token)

    @application.delete("/v1/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_token(
        token_id: UUID,
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> None:
        """Permanently revoke an owned token or a managed account token."""
        token = await AccountTokenRecord.all().select_related("account").get_or_none(id=token_id)
        if token is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token does not exist")
        if token.account.id != principal.account.id:
            await require_account_grant(Grant.TOKENS_MANAGE, principal)
        await token.delete()

    return application


async def create_management_server(
    application: FastAPI,
    authority: LocalCertificateAuthority,
    *,
    host: str,
    port: int,
) -> Server:
    """Create an HTTPS-only Uvicorn server using the active provider leaf."""
    context = await authority.get_active_server_ssl_context()
    configuration = Config(
        application,
        host=host,
        port=port,
        ssl_context_factory=lambda _configuration, _default_factory: context,
    )
    return Server(configuration)
