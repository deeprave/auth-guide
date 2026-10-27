"""HTTPS-only management API application factory."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Self
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, model_validator
from tortoise.exceptions import IntegrityError
from tortoise.transactions import in_transaction
from uvicorn import Config, Server

from auth_guide.accounts import (
    AccountRecord,
    AccountStore,
    AccountTokenRecord,
    Grant,
    generate_account_token,
    resolve_account_token,
)
from auth_guide.accounts.models import AccountExpiryTimezoneError, normalise_account_email
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
    account_email: str | None = None


class TokenCreationResponse(TokenResponse):
    """A newly issued token, including its once-only raw bearer value."""

    token: str


class TokenLabelUpdate(RequestModel):
    """The only mutable account-token property."""

    label: str = Field(min_length=1)


class AccountCreationRequest(RequestModel):
    """Privileged account creation input."""

    email: str
    grants: list[Grant]
    full_name: str | None = None
    expires_at: datetime | None = None
    password: str = Field(min_length=12)


class AccountSelfUpdate(RequestModel):
    """Fields an active account may update on itself."""

    email: str | None = None
    full_name: str | None = None


class AccountManagementUpdate(RequestModel):
    """Fields an account manager may alter on another account."""

    grants: list[Grant] | None = None
    add_grants: list[Grant] | None = None
    remove_grants: list[Grant] | None = None
    reactivate: bool | None = None

    @model_validator(mode="after")
    def validate_grant_operation(self) -> Self:
        """Keep complete replacement distinct from atomic grant deltas."""
        if "grants" in self.model_fields_set and (
            "add_grants" in self.model_fields_set or "remove_grants" in self.model_fields_set
        ):
            raise ValueError("Grant replacement cannot be combined with grant deltas")
        return self


class PasswordUpdate(RequestModel):
    """A password replacement submitted through the HTTPS control plane."""

    password: str = Field(min_length=12)


def _account_validation_detail(error: ValueError) -> str:
    """Keep safe, actionable account-validation diagnostics at the API boundary."""
    if isinstance(error, AccountExpiryTimezoneError):
        return str(error)
    return "Account values are invalid"


def _require_timezone_aware_expiry(expires_at: datetime | None) -> None:
    """Reject an API expiry whose parsed timestamp omitted a timezone."""
    if expires_at is not None and (expires_at.tzinfo is None or expires_at.utcoffset() is None):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Account expiry must include a timezone",
        )


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

    async def require_accounts_manage(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
    ) -> AuthenticatedPrincipal:
        """Require account-management authority for a privileged mutation."""
        return await require_account_grant(Grant.ACCOUNTS_MANAGE, principal)

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

    async def resolve_account_by_email(email: str) -> AccountRecord:
        """Resolve one complete account record from its validated email selector."""
        try:
            normalised_email = await normalise_account_email(email)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Account email is invalid"
            ) from error
        account = await AccountRecord.including_inactive().get_or_none(
            email_comparison=normalised_email["email_comparison"]
        )
        if account is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account does not exist")
        return account

    async def resolve_account_by_id(account_id: UUID) -> AccountRecord:
        """Resolve one complete account record from its immutable UUID selector."""
        account = await AccountRecord.including_inactive().get_or_none(id=account_id)
        if account is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account does not exist")
        return account

    async def update_managed_account(
        update: AccountManagementUpdate,
        *,
        account_id: UUID | None = None,
        email: str | None = None,
    ) -> AccountRecord:
        """Atomically apply a complete grant replacement or grant deltas."""
        email_comparison: str | None = None
        if email is not None:
            try:
                email_comparison = (await normalise_account_email(email))["email_comparison"]
            except ValueError as error:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Account email is invalid",
                ) from error

        async with in_transaction() as connection:
            accounts = AccountRecord.including_inactive().using_db(connection).select_for_update()
            if account_id is not None:
                account = await accounts.get_or_none(id=account_id)
            else:
                account = await accounts.get_or_none(email_comparison=email_comparison)
            if account is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account does not exist")

            update_fields: list[str] = []
            if "grants" in update.model_fields_set:
                account.grants = update.grants or []
                update_fields.append("grants")
            elif "add_grants" in update.model_fields_set or "remove_grants" in update.model_fields_set:
                grants = set(account.grants)
                grants.update(str(grant) for grant in update.add_grants or [])
                grants.difference_update(str(grant) for grant in update.remove_grants or [])
                account.grants = sorted(grants)
                update_fields.append("grants")
            if update.reactivate is True:
                account.expires_at = None
                update_fields.append("expires_at")
            if update_fields:
                try:
                    await account.save(using_db=connection, update_fields=update_fields)
                except ValueError as error:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                        detail=_account_validation_detail(error),
                    ) from error
            return account

    @application.get("/v1/accounts", response_model=list[AccountResponse] | AccountResponse)
    async def list_accounts(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_principal)],
        email: Annotated[str | None, Query()] = None,
    ) -> list[AccountRecord] | AccountRecord:
        """List every account, including inactive records, for account readers."""
        if email is not None:
            try:
                email_comparison = (await normalise_account_email(email))["email_comparison"]
            except ValueError as error:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Account email is invalid"
                ) from error
            if email_comparison == principal.account.email_comparison:
                return principal.account
            await require_account_grant(Grant.ACCOUNTS_READ, principal)
            return await resolve_account_by_email(email)
        await require_account_grant(Grant.ACCOUNTS_READ, principal)
        return await AccountRecord.including_inactive().order_by("email_comparison")

    @application.patch("/v1/accounts", response_model=AccountResponse)
    async def manage_account_by_email(
        update: AccountManagementUpdate,
        email: Annotated[str, Query()],
        _: Annotated[AuthenticatedPrincipal, Depends(require_accounts_manage)],
    ) -> AccountRecord:
        """Apply privileged account changes using an email selector."""
        return await update_managed_account(update, email=email)

    @application.post("/v1/accounts/password", response_model=AccountResponse)
    async def reset_account_password_by_email(
        update: PasswordUpdate,
        email: Annotated[str, Query()],
        _: Annotated[AuthenticatedPrincipal, Depends(require_accounts_manage)],
        store: Annotated[AccountStore, Depends(require_store)],
    ) -> AccountRecord:
        """Reset an account password using an email selector."""
        account = await resolve_account_by_email(email)
        await store.reset_password(account, update.password)
        return account

    @application.delete("/v1/accounts", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_account_by_email(
        email: Annotated[str, Query()],
        _: Annotated[AuthenticatedPrincipal, Depends(require_accounts_manage)],
    ) -> None:
        """Permanently delete an account using an email selector."""
        await (await resolve_account_by_email(email)).delete()

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
        _require_timezone_aware_expiry(request.expires_at)
        account = AccountRecord(
            email=request.email,
            grants=request.grants,
            full_name=request.full_name,
            expires_at=request.expires_at,
        )
        try:
            await store.create_account(account, request.password)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=_account_validation_detail(error),
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
        """Mutate grants or reactivate another account without editing its profile."""
        return await update_managed_account(update, account_id=account_id)

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
        account_email: Annotated[str | None, Query()] = None,
    ) -> list[TokenResponse]:
        """List own token metadata, or another account's with token management."""
        if account_id is not None and account_email is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Specify one account selector"
            )
        if account_id is not None or account_email is not None:
            await require_account_grant(Grant.TOKENS_MANAGE, principal)
        target_account_id = principal.account.id
        if account_id is not None:
            target_account_id = (await resolve_account_by_id(account_id)).id
        if account_email is not None:
            target_account_id = (await resolve_account_by_email(account_email)).id
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
        if request.account_id is not None and request.account_email is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Specify one account selector"
            )
        if request.account_id is not None or request.account_email is not None:
            await require_account_grant(Grant.TOKENS_MANAGE, principal)
        target_account_id = principal.account.id
        if request.account_id is not None:
            target_account_id = (await resolve_account_by_id(request.account_id)).id
        if request.account_email is not None:
            target_account_id = (await resolve_account_by_email(request.account_email)).id
        if target_account_id == principal.account.id:
            account = principal.account
        else:
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
    install_signal_handlers: bool = True,
) -> Server:
    """Create an HTTPS-only Uvicorn server using the active provider leaf."""
    from auth_guide.cli.logging import ensure_uvicorn_access_policy

    ensure_uvicorn_access_policy()
    context = await authority.get_active_server_ssl_context()
    configuration = Config(
        application,
        host=host,
        port=port,
        ssl_context_factory=lambda _configuration, _default_factory: context,
        access_log=True,
        log_config=None,
    )
    server_type = Server if install_signal_handlers else _LifecycleManagedServer
    return server_type(configuration)


class _LifecycleManagedServer(Server):
    """Leave process signals to the provider lifecycle owner."""

    def install_signal_handlers(self) -> None:
        """Avoid replacing the server runtime's SIGTERM/SIGINT/SIGHUP handlers."""
