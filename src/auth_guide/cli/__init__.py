"""Administration command-line interface for the reference provider."""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import NoReturn
from urllib.parse import quote
from uuid import UUID

import anyio
import click

from auth_guide.accounts.models import validate_account_email
from auth_guide.cli.client import (
    DEFAULT_TIMEOUT,
    SETUP_TIMEOUT,
    ManagementAPIClient,
    ManagementAPIError,
    ManagementClientConfiguration,
)
from auth_guide.cli.config import create_configuration_file, resolve_configuration, resolve_configuration_path
from auth_guide.cli.logging import configure_logging, configure_safe_console_logging, get_logger
from auth_guide.secrets import PlatformSecretProvider, SecretProviderError
from auth_guide.system_trust import TrustStoreError, select_system_trust_store
from auth_guide.tls import (
    CertificateAuthorityAlreadyInitialisedError,
    CertificateAuthorityNotInitialisedError,
    LocalCertificateAuthority,
)


class AdministrationGroup(click.Group):
    """Present the primary operator workflow before supporting commands."""

    command_order = ("account", "token", "grant", "ca", "init")

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        """Remember whether any nested command requested local help."""
        ctx.meta["help_requested"] = "--help" in args or "-h" in args
        return super().parse_args(ctx, args)

    def list_commands(self, ctx: click.Context) -> list[str]:
        """List primary commands in their deliberate operator-facing order."""
        commands = super().list_commands(ctx)
        if _operator_token_is_configured(ctx):
            commands = [command for command in commands if command != "init"]
        order = {name: index for index, name in enumerate(self.command_order)}
        return sorted(commands, key=lambda name: order.get(name, len(order)))


def _operator_token_is_configured(context: click.Context) -> bool:
    """Return whether the invocation supplies an operator bearer token."""
    return bool(os.environ.get("AUTH_GUIDE_TOKEN")) or bool(
        context.obj.get("prompt_token") if isinstance(context.obj, dict) else False
    )


def _operational_failure(message: str) -> NoReturn:
    """Report a completed command's operational failure through the console logger."""
    get_logger("auth_guide").error("Error: %s", message)
    raise click.exceptions.Exit(1)


class ConfigurationGroup(click.Group):
    """Hide initialisation once the selected configuration file exists."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        """List diagnostic commands and initialisation only when it is applicable."""
        commands = super().list_commands(ctx)
        configuration = ctx.obj.get("configuration") if isinstance(ctx.obj, dict) else None
        if configuration is not None and configuration.configuration_file.exists():
            return [command for command in commands if command != "init"]
        return commands


@click.group(cls=AdministrationGroup)
@click.option("--config", "configuration_file", "-C", type=click.Path(path_type=Path), help="Configuration TOML file.")
@click.option("--listen", "listen", "-L", help="Provider HTTPS listen address.")
@click.option("--address", "address", "-A", help="Provider HTTPS address.")
@click.option("--token", "prompt_token", is_flag=True, help="Prompt for the operator bearer token.")
@click.option(
    "--log-console",
    "log_level_console",
    type=click.Choice(["TRACE", "DEBUG", "INFO", "WARN", "CRITICAL"], case_sensitive=False),
)
@click.option(
    "--log-level",
    "log_level",
    "-v",
    type=click.Choice(["TRACE", "DEBUG", "INFO", "WARN", "CRITICAL"], case_sensitive=False),
)
@click.option("--log-file", "log_file", "-l", type=click.Path(path_type=Path))
@click.option("--log-syslog", "log_syslog", "-S", is_flag=True, default=None)
@click.option("--no-cli-log", "cli_log", "-N", flag_value=False, default=None)
@click.pass_context
def cli(
    context: click.Context,
    configuration_file: Path | None,
    listen: str | None,
    address: str | None,
    prompt_token: bool,
    log_level_console: str | None,
    log_level: str | None,
    log_file: Path | None,
    log_syslog: bool | None,
    cli_log: bool | None,
) -> None:
    """Administer an auth-guide provider through its HTTPS API."""
    context.ensure_object(dict)
    safe_logger = configure_safe_console_logging()
    try:
        configuration = resolve_configuration(
            resolve_configuration_path(configuration_file),
            listen=listen,
            address=address,
            log_level_console=log_level_console,
            log_level=log_level,
            log_file=None if log_file is None else str(log_file),
            log_syslog=log_syslog,
            cli_log=cli_log,
        )
    except (OSError, ValueError) as error:
        safe_logger.error("Error: Unable to load configuration: %s", error)
        raise click.exceptions.Exit(1) from error
    if _is_help_request(context):
        context.obj["logger"] = safe_logger
        context.obj["configuration"] = configuration
        context.obj["address"] = configuration.address
        context.obj["prompt_token"] = prompt_token
        return
    try:
        context.obj["logger"] = configure_logging(configuration, cli_only=True)
    except (OSError, ValueError) as error:
        get_logger("auth_guide").error("Error: Unable to initialise persistent logging: %s", error)
        raise click.exceptions.Exit(1) from error
    context.obj["configuration"] = configuration
    context.obj["address"] = configuration.address
    context.obj["prompt_token"] = prompt_token


def _operator_token(context: click.Context) -> str:
    """Obtain the bearer only when a command actually needs it."""
    token = os.environ.get("AUTH_GUIDE_TOKEN")
    if token:
        return token
    if context.obj["prompt_token"]:
        return click.prompt("Operator token", hide_input=True)
    _operational_failure("AUTH_GUIDE_TOKEN or --token is required")


def _account_selector(account: str) -> dict[str, object]:
    """Build exactly one API account selector from a human CLI argument."""
    account = account.strip()
    try:
        account_id = UUID(account)
    except ValueError:
        return {"account_email": account}
    return {"account_id": str(account_id)}


def _validated_account_email(email: str) -> str:
    """Validate a local account email before collecting a password."""
    try:
        return validate_account_email(email)
    except ValueError as error:
        _operational_failure(str(error))


def _validated_account_selector(account: str) -> dict[str, object]:
    """Validate an account selector locally before collecting a password."""
    selector = _account_selector(account)
    account_email = selector.get("account_email")
    if account_email is not None:
        selector["account_email"] = _validated_account_email(str(account_email))
    return selector


def _token_record_id(token_id: str) -> UUID:
    """Validate a non-secret token record identifier before using it in a path."""
    try:
        return UUID(token_id)
    except ValueError:
        _operational_failure("Token identifier must be a UUID")


def _prompt_password(label: str) -> str:
    """Collect a new password only after the command is ready to submit it."""
    while True:
        password = click.prompt(label, hide_input=True, confirmation_prompt=True)
        if len(password) >= 12:
            return password
        get_logger("auth_guide").error("Error: Password must contain at least 12 characters")


def _validated_expiry(expires_at: str | None) -> str | None:
    """Require an ISO-8601 expiry with an explicit timezone before prompting."""
    if expires_at is None:
        return None
    try:
        parsed = datetime.fromisoformat(expires_at)
    except ValueError:
        _operational_failure("Account expiry must be an ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _operational_failure("Account expiry must include a timezone")
    return expires_at


def _is_help_request(context: click.Context) -> bool:
    """Recognise nested help before persistent logging setup is required."""
    return context.resilient_parsing or bool(context.meta.get("help_requested"))


async def _request(
    address: str,
    token: str | None,
    method: str,
    path: str,
    json_body: dict[str, object] | None = None,
    *,
    setup: bool = False,
) -> object:
    """Run one prepared management request asynchronously."""
    try:
        client = ManagementAPIClient(ManagementClientConfiguration(address, token))
        timeout = SETUP_TIMEOUT if setup else DEFAULT_TIMEOUT
        return await client.request(method, path, json=json_body, timeout=timeout)
    except (ManagementAPIError, ValueError) as error:
        _operational_failure(str(error))


@cli.group("config", cls=ConfigurationGroup)
def config() -> None:
    """Manage non-secret CLI configuration."""


@config.command("init")
@click.pass_context
def initialise_config(context: click.Context) -> None:
    """Create an absent commented configuration scaffold."""
    target = context.obj["configuration"].configuration_file
    try:
        anyio.run(create_configuration_file, anyio.Path(target))
    except FileExistsError:
        _operational_failure(f"Configuration file already exists: {target}")
    except OSError as error:
        _operational_failure(f"Unable to create configuration file: {error}")
    get_logger("auth_guide").info("Created configuration file: %s", target)


@config.command("path")
@click.pass_context
def show_configuration_path(context: click.Context) -> None:
    """Display the selected configuration file path without creating it."""
    click.echo(context.obj["configuration"].configuration_file)


@cli.command("init")
@click.argument("email")
@click.option("--remove-orphan-key", is_flag=True)
@click.pass_context
def initialise_provider(context: click.Context, email: str, remove_orphan_key: bool) -> None:
    """Create the first administrator and display its credentials once."""
    if _operator_token_is_configured(context):
        _operational_failure("Initial setup cannot run while an operator token is configured")
    if not sys.stdout.isatty():
        _operational_failure("Initial setup requires a terminal stdout for generated credentials")
    path = "/v1/setup?remove_orphan_key=true" if remove_orphan_key else "/v1/setup"
    result = anyio.run(_request_setup, context.obj["address"], path, email)
    if not isinstance(result, dict):
        _operational_failure("Provider returned an invalid setup response")
    password = result.get("password")
    token = result.get("token")
    if not isinstance(password, str) or not password or not isinstance(token, str) or not token:
        _operational_failure("Provider returned an invalid setup response")
    click.echo(f"Initial password: {password}")
    click.echo(f"Initial token: {token}")


async def _request_setup(address: str, path: str, email: str) -> object:
    """Send setup using its unbounded response wait for platform-keyring prompts."""
    return await _request(address, None, "POST", path, {"email": email}, setup=True)


async def _initialise_certificate_authority() -> None:
    """Create the provider-local authority through its owned secret boundary."""
    async with PlatformSecretProvider("auth-guide") as secrets:
        async with LocalCertificateAuthority(secrets=secrets) as authority:
            await authority.initialise()


async def _change_system_trust(remove: bool) -> None:
    """Install or remove the current public CA through the selected platform facade."""
    async with PlatformSecretProvider("auth-guide") as secrets:
        async with LocalCertificateAuthority(secrets=secrets) as authority:
            trust_store = await select_system_trust_store()
            if remove:
                await authority.remove_system_trust(trust_store)
            else:
                await authority.install_system_trust(trust_store)


@cli.group("ca")
def certificate_authority() -> None:
    """Manage the provider-local certificate authority."""


@certificate_authority.command("init")
def initialise_certificate_authority() -> None:
    """Create the local CA and its default localhost certificate."""
    try:
        anyio.run(_initialise_certificate_authority)
    except (
        CertificateAuthorityAlreadyInitialisedError,
        OSError,
        PermissionError,
        SecretProviderError,
        ValueError,
    ) as error:
        _operational_failure(str(error))
    get_logger("auth_guide").info("Local certificate authority initialised.")


@certificate_authority.group("trust")
def certificate_trust() -> None:
    """Install or remove the public CA from system trust."""


@certificate_trust.command("install")
def install_certificate_trust() -> None:
    """Install the current local CA in the supported system trust store."""
    try:
        anyio.run(_change_system_trust, False)
    except (
        CertificateAuthorityNotInitialisedError,
        OSError,
        PermissionError,
        SecretProviderError,
        TrustStoreError,
        ValueError,
    ) as error:
        _operational_failure(str(error))
    get_logger("auth_guide").info("Local certificate authority installed in system trust.")


@certificate_trust.command("remove")
def remove_certificate_trust() -> None:
    """Remove the current local CA from the supported system trust store."""
    try:
        anyio.run(_change_system_trust, True)
    except (
        CertificateAuthorityNotInitialisedError,
        OSError,
        PermissionError,
        SecretProviderError,
        TrustStoreError,
        ValueError,
    ) as error:
        _operational_failure(str(error))
    get_logger("auth_guide").info("Local certificate authority removed from system trust.")


@cli.group("account")
def account() -> None:
    """Manage provider accounts."""


@account.command("list")
@click.pass_context
def list_accounts(context: click.Context) -> None:
    """List accounts visible to the authenticated operator."""
    result = anyio.run(_request, context.obj["address"], _operator_token(context), "GET", "/v1/accounts")
    click.echo(json.dumps(result, indent=2, default=str))


@account.command("me")
@click.pass_context
def read_own_account(context: click.Context) -> None:
    """Show the authenticated account's complete non-secret record."""
    result = anyio.run(_request, context.obj["address"], _operator_token(context), "GET", "/v1/accounts/me")
    click.echo(json.dumps(result, indent=2, default=str))


@account.command("update")
@click.option("--email")
@click.option("--full-name")
@click.pass_context
def update_own_account(context: click.Context, email: str | None, full_name: str | None) -> None:
    """Update the authenticated account's email or full name."""
    if email is None and full_name is None:
        raise click.UsageError("Specify --email or --full-name")
    body: dict[str, object] = {}
    if email is not None:
        body["email"] = email
    if full_name is not None:
        body["full_name"] = full_name
    result = anyio.run(_request, context.obj["address"], _operator_token(context), "PATCH", "/v1/accounts/me", body)
    click.echo(json.dumps(result, indent=2, default=str))


@account.command("password")
@click.pass_context
def replace_own_password(context: click.Context) -> None:
    """Replace the authenticated account's password through a hidden prompt."""
    token = _operator_token(context)
    password = _prompt_password("New password")
    result = anyio.run(
        _request,
        context.obj["address"],
        token,
        "POST",
        "/v1/accounts/me/password",
        {"password": password},
    )
    click.echo(json.dumps(result, indent=2, default=str))


@account.command("close")
@click.pass_context
def close_own_account(context: click.Context) -> None:
    """Make the authenticated account immediately inactive."""
    result = anyio.run(_request, context.obj["address"], _operator_token(context), "POST", "/v1/accounts/me/close")
    click.echo(json.dumps(result, indent=2, default=str))


@account.command("create")
@click.argument("email")
@click.option("--grant", "grants", multiple=True)
@click.option("--full-name")
@click.option("--expires-at")
@click.pass_context
def create_account(
    context: click.Context,
    email: str,
    grants: tuple[str, ...],
    full_name: str | None,
    expires_at: str | None,
) -> None:
    """Create an account with a prompted initial password."""
    token = _operator_token(context)
    email = _validated_account_email(email)
    expires_at = _validated_expiry(expires_at)
    password = _prompt_password("Initial password")
    body: dict[str, object] = {"email": email, "grants": list(grants), "password": password}
    if full_name is not None:
        body["full_name"] = full_name
    if expires_at is not None:
        body["expires_at"] = expires_at
    result = anyio.run(_request, context.obj["address"], token, "POST", "/v1/accounts", body)
    click.echo(json.dumps(result, indent=2, default=str))


@account.command("delete")
@click.argument("account")
@click.pass_context
def delete_account(context: click.Context, account: str) -> None:
    """Permanently delete an account selected by UUID or email."""
    selector = _account_selector(account)
    if "account_id" in selector:
        path = f"/v1/accounts/{selector['account_id']}"
    else:
        path = f"/v1/accounts?email={quote(str(selector['account_email']), safe='')}"
    anyio.run(_request, context.obj["address"], _operator_token(context), "DELETE", path)
    get_logger("auth_guide").info("Account deleted.")


@account.command("show")
@click.argument("account")
@click.pass_context
def show_account(context: click.Context, account: str) -> None:
    """Show one account selected by UUID or email."""
    selector = _account_selector(account)
    path = (
        f"/v1/accounts/{selector['account_id']}"
        if "account_id" in selector
        else f"/v1/accounts?email={quote(str(selector['account_email']), safe='')}"
    )
    result = anyio.run(_request, context.obj["address"], _operator_token(context), "GET", path)
    click.echo(json.dumps(result, indent=2, default=str))


@account.command("reactivate")
@click.argument("account")
@click.pass_context
def reactivate_account(context: click.Context, account: str) -> None:
    """Reactivate an account selected by UUID or email."""
    result = anyio.run(
        _replace_account,
        context.obj["address"],
        _operator_token(context),
        account,
        {"reactivate": True},
    )
    click.echo(json.dumps(result, indent=2, default=str))


@account.command("reset-password")
@click.argument("account")
@click.pass_context
def reset_account_password(context: click.Context, account: str) -> None:
    """Reset another account's password through a hidden prompt."""
    token = _operator_token(context)
    selector = _validated_account_selector(account)
    password = _prompt_password("New password")
    path = (
        f"/v1/accounts/{selector['account_id']}/password"
        if "account_id" in selector
        else f"/v1/accounts/password?email={quote(str(selector['account_email']), safe='')}"
    )
    result = anyio.run(_request, context.obj["address"], token, "POST", path, {"password": password})
    click.echo(json.dumps(result, indent=2, default=str))


@cli.group("grant")
def grant() -> None:
    """Manage account grants."""


@grant.command("list")
@click.argument("account")
@click.pass_context
def list_grants(context: click.Context, account: str) -> None:
    """List an account's effective grants."""
    selector = _account_selector(account)
    path = (
        f"/v1/accounts/{selector['account_id']}"
        if "account_id" in selector
        else f"/v1/accounts?email={quote(str(selector['account_email']), safe='')}"
    )
    result = anyio.run(_request, context.obj["address"], _operator_token(context), "GET", path)
    if not isinstance(result, dict):
        _operational_failure("Provider returned an invalid account response")
    click.echo(json.dumps(result.get("grants", []), indent=2))


async def _replace_account(address: str, token: str, account: str, update: dict[str, object]) -> object:
    """Apply a privileged account update through its existing management route."""
    selector = _account_selector(account)
    if "account_id" in selector:
        return await _request(address, token, "PATCH", f"/v1/accounts/{selector['account_id']}", update)
    return await _request(
        address,
        token,
        "PATCH",
        f"/v1/accounts?email={quote(str(selector['account_email']), safe='')}",
        update,
    )


async def _replace_grants(address: str, token: str, account: str, grants: list[str]) -> object:
    """Replace one account's grant set through its existing management route."""
    return await _replace_account(address, token, account, {"grants": grants})


@grant.command("set")
@click.argument("account")
@click.argument("grants", nargs=-1)
@click.option("--clear", "confirm_empty", is_flag=True, help="Clear every grant when no grants are supplied.")
@click.pass_context
def set_grants(context: click.Context, account: str, grants: tuple[str, ...], confirm_empty: bool) -> None:
    """Replace an account's complete grant set; omitted grants clear it with --clear."""
    if not grants and not confirm_empty:
        _operational_failure("Clearing every grant requires --clear")
    result = anyio.run(_replace_grants, context.obj["address"], _operator_token(context), account, list(grants))
    click.echo(json.dumps(result, indent=2, default=str))


async def _mutate_grants(address: str, token: str, account: str, grant: str, remove: bool) -> object:
    """Request an atomic provider-side addition or removal of one grant."""
    operation = "remove_grants" if remove else "add_grants"
    return await _replace_account(address, token, account, {operation: [grant]})


@grant.command("add")
@click.argument("account")
@click.argument("grant")
@click.pass_context
def add_grant(context: click.Context, account: str, grant: str) -> None:
    """Add one grant without discarding the account's other grants."""
    result = anyio.run(_mutate_grants, context.obj["address"], _operator_token(context), account, grant, False)
    click.echo(json.dumps(result, indent=2, default=str))


@grant.command("remove")
@click.argument("account")
@click.argument("grant")
@click.pass_context
def remove_grant(context: click.Context, account: str, grant: str) -> None:
    """Remove one grant without changing the account's other grants."""
    result = anyio.run(_mutate_grants, context.obj["address"], _operator_token(context), account, grant, True)
    click.echo(json.dumps(result, indent=2, default=str))


@cli.group("token")
def token() -> None:
    """Manage account access tokens."""


@token.command("create")
@click.argument("label")
@click.option("--scope", "scopes", multiple=True)
@click.option("--account")
@click.pass_context
def create_token(context: click.Context, label: str, scopes: tuple[str, ...], account: str | None) -> None:
    """Create a new account access token."""
    if not sys.stdout.isatty():
        _operational_failure("Token creation requires a terminal stdout for the generated credential")
    body: dict[str, object] = {"label": label, "scopes": list(scopes)}
    if account is not None:
        body.update(_account_selector(account))
    result = anyio.run(_request, context.obj["address"], _operator_token(context), "POST", "/v1/tokens", body)
    if not isinstance(result, dict) or not isinstance(result.get("token"), str):
        _operational_failure("Provider returned an invalid token response")
    metadata = {key: value for key, value in result.items() if key != "token"}
    click.echo(json.dumps(metadata, indent=2, default=str))
    click.echo(f"Token: {result['token']}")


@token.command("list")
@click.option("--account")
@click.pass_context
def list_tokens(context: click.Context, account: str | None) -> None:
    """List the authenticated account's token metadata."""
    path = "/v1/tokens"
    if account is not None:
        selector = _account_selector(account)
        if "account_id" in selector:
            path = f"/v1/tokens?account_id={selector['account_id']}"
        else:
            path = f"/v1/tokens?account_email={quote(str(selector['account_email']), safe='')}"
    result = anyio.run(_request, context.obj["address"], _operator_token(context), "GET", path)
    click.echo(json.dumps(result, indent=2, default=str))


@token.command("relabel")
@click.argument("token_id")
@click.argument("label")
@click.pass_context
def relabel_token(context: click.Context, token_id: str, label: str) -> None:
    """Change an existing token's non-secret label."""
    token_record_id = _token_record_id(token_id)
    result = anyio.run(
        _request,
        context.obj["address"],
        _operator_token(context),
        "PATCH",
        f"/v1/tokens/{token_record_id}",
        {"label": label},
    )
    click.echo(json.dumps(result, indent=2, default=str))


@token.command("revoke")
@click.argument("token_id")
@click.pass_context
def revoke_token(context: click.Context, token_id: str) -> None:
    """Permanently revoke one token by its non-secret record identifier."""
    token_record_id = _token_record_id(token_id)
    anyio.run(_request, context.obj["address"], _operator_token(context), "DELETE", f"/v1/tokens/{token_record_id}")
    get_logger("auth_guide").info("Token revoked.")
