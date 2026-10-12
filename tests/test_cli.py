"""Behaviour tests for the administration CLI."""

import asyncio
import logging
import os
import socket
import ssl

import anyio
import httpx
import pytest
from anyio import Path as AsyncPath
from click.testing import CliRunner

from auth_guide.accounts import AccountRecord, AccountStore, AccountTokenRecord, generate_account_token
from auth_guide.cli import cli
from auth_guide.cli.config import create_configuration_file, resolve_configuration, resolve_configuration_path
from auth_guide.cli.logging import RedactingFormatter, configure_logging
from auth_guide.management_api import create_management_application, create_management_server
from auth_guide.secrets import PlatformSecretProvider
from auth_guide.tls import LocalCertificateAuthority


class MemoryKeyring:
    """Hold test-only provider secrets outside the CLI process."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service_name: str, username: str) -> str | None:
        """Return one stored provider secret."""
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        """Store one provider secret."""
        self.values[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        """Remove one provider secret."""
        del self.values[(service_name, username)]


@pytest.mark.anyio
async def test_nested_help_is_local_without_provider_connection() -> None:
    """Nested help succeeds without resolving configuration or contacting a provider."""
    result = CliRunner().invoke(cli, ["token", "create", "--help"])

    assert result.exit_code == 0
    assert "Create a new account access token" in result.output


@pytest.mark.anyio
async def test_root_help_prioritises_the_operator_workflow() -> None:
    """Root help presents the primary administration commands in workflow order."""
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    commands = result.output.split("Commands:\n", maxsplit=1)[1]
    positions = [commands.index(f"  {name}") for name in ("account", "token", "grant", "ca", "init")]
    assert positions == sorted(positions)


@pytest.mark.anyio
async def test_root_help_hides_bootstrap_when_an_operator_has_a_token(monkeypatch) -> None:
    """A provider-issued bearer establishes that first setup has completed."""
    monkeypatch.setenv("AUTH_GUIDE_TOKEN", "agt_example")

    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    commands = result.output.split("Commands:\n", maxsplit=1)[1]
    assert "  init" not in commands


@pytest.mark.anyio
@pytest.mark.parametrize("arguments", [[], ["--token"]])
async def test_bootstrap_rejects_an_operator_token_before_contacting_the_provider(
    monkeypatch, arguments: list[str]
) -> None:
    """Bootstrap fails locally when the invocation already carries a bearer."""
    if not arguments:
        monkeypatch.setenv("AUTH_GUIDE_TOKEN", "agt_example")

    result = CliRunner().invoke(cli, [*arguments, "init", "admin@example.test"])

    assert result.exit_code == 1
    assert "Initial setup cannot run while an operator token is configured" in result.output


@pytest.mark.anyio
async def test_connection_failure_is_a_concise_cli_error() -> None:
    """An unavailable provider does not expose a transport traceback to operators."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    environment = dict(os.environ)
    environment["AUTH_GUIDE_TOKEN"] = "agt_example"
    result = await anyio.run_process(
        ["uv", "run", "auth-guide", "--address", f"https://127.0.0.1:{port}", "account", "me"],
        env=environment,
        check=False,
    )

    output = result.stderr.decode()
    assert result.returncode == 1
    assert f"Could not reach the management API at https://127.0.0.1:{port}" in output
    assert "Traceback" not in output


@pytest.mark.anyio
async def test_unavailable_persistent_log_path_is_a_concise_console_error(tmp_path) -> None:
    """Persistent-log setup failure leaves a usable Rich console error path."""
    log_file = tmp_path / "missing" / "auth-guide.log"

    result = await anyio.run_process(
        ["uv", "run", "auth-guide", "--log-file", str(log_file), "account", "me"],
        check=False,
    )

    output = result.stderr.decode()
    assert result.returncode == 1
    assert "Error: Unable to initialise persistent logging:" in output
    assert "Traceback" not in output


@pytest.mark.anyio
async def test_invalid_environment_log_level_is_a_concise_console_error(tmp_path) -> None:
    """Invalid non-CLI log configuration never exposes an exception traceback."""
    environment = dict(os.environ)
    environment["AG_LOGLEVEL"] = "WARNING"

    result = await anyio.run_process(
        ["uv", "run", "auth-guide", "--config", str(tmp_path / "config.toml"), "account", "me"],
        env=environment,
        check=False,
    )

    output = result.stderr.decode()
    assert result.returncode == 1
    assert "Error: Unable to initialise persistent logging: Log level must be" in output
    assert "Traceback" not in output


@pytest.mark.anyio
@pytest.mark.parametrize("configuration_content", ["not = [valid", "listen = 3"])
async def test_invalid_configuration_is_a_concise_console_error(tmp_path, configuration_content: str) -> None:
    """Unreadable configuration values do not become Click usage or tracebacks."""
    configuration_file = tmp_path / "config.toml"
    await AsyncPath(configuration_file).write_text(configuration_content, encoding="utf-8")

    result = CliRunner().invoke(cli, ["--config", str(configuration_file), "account", "me"])

    assert result.exit_code == 1
    assert "Error: Unable to load configuration:" in result.output
    assert "Usage:" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.anyio
async def test_unreadable_configuration_is_a_concise_console_error(tmp_path) -> None:
    """Configuration I/O failures do not expose tracebacks before logging is configured."""
    configuration_file = tmp_path / "configuration-directory"
    await AsyncPath(configuration_file).mkdir()

    result = CliRunner().invoke(cli, ["--config", str(configuration_file), "account", "me"])

    assert result.exit_code == 1
    assert "Error: Unable to load configuration:" in result.output
    assert "Usage:" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.anyio
@pytest.mark.parametrize(
    "command",
    [
        [],
        ["config"],
        ["config", "init"],
        ["config", "path"],
        ["ca"],
        ["ca", "init"],
        ["ca", "trust"],
        ["ca", "trust", "install"],
        ["ca", "trust", "remove"],
        ["init"],
        ["account"],
        ["account", "list"],
        ["account", "me"],
        ["account", "update"],
        ["account", "password"],
        ["account", "close"],
        ["account", "create"],
        ["account", "show"],
        ["account", "reactivate"],
        ["account", "reset-password"],
        ["account", "delete"],
        ["grant"],
        ["grant", "list"],
        ["grant", "set"],
        ["grant", "add"],
        ["grant", "remove"],
        ["token"],
        ["token", "list"],
        ["token", "create"],
        ["token", "relabel"],
        ["token", "revoke"],
    ],
)
async def test_every_command_help_is_local(command: list[str]) -> None:
    """Every command surface provides help without resolving an operator bearer."""
    result = CliRunner().invoke(cli, [*command, "--help"])

    assert result.exit_code == 0
    assert "Usage:" in result.output


@pytest.mark.anyio
async def test_configuration_uses_cli_then_environment_then_toml_then_default(tmp_path, monkeypatch) -> None:
    """Each setting has independent, predictable configuration precedence."""
    configuration_file = tmp_path / "config.toml"
    await AsyncPath(configuration_file).write_text(
        'listen = "https://file-listen.example:9443"\n'
        'address = "https://file-address.example:9444"\n'
        'log_level_console = "WARN"\n'
        'log_level = "INFO"\nlog_file = "/tmp/auth-guide.log"\nlog_syslog = true\nlog_cli = false\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("AG_LISTEN", "https://environment-listen.example:9445")
    monkeypatch.setenv("AG_LOGCONSOLE", "DEBUG")

    configuration = resolve_configuration(
        configuration_file,
        listen="https://command-line-listen.example:9446",
    )

    assert configuration.listen == "https://command-line-listen.example:9446"
    assert configuration.address == "https://file-address.example:9444"
    assert configuration.log_level_console == "DEBUG"
    assert configuration.log_level == "INFO"
    assert configuration.log_file == "/tmp/auth-guide.log"
    assert configuration.log_syslog is True
    assert configuration.cli_log is False


@pytest.mark.anyio
async def test_configuration_file_selection_prefers_command_line_then_environment(tmp_path) -> None:
    """Selecting configuration itself follows the documented explicit precedence."""
    command_line = tmp_path / "command-line.toml"
    environment = tmp_path / "environment.toml"

    selected = resolve_configuration_path(command_line, environ={"AG_CONFIG": str(environment)})

    assert selected == command_line
    assert resolve_configuration_path(environ={"AG_CONFIG": str(environment)}) == environment


@pytest.mark.anyio
async def test_config_init_creates_an_absent_non_secret_scaffold(tmp_path) -> None:
    """Configuration creation is explicit and never overwrites an existing file."""
    configuration_file = AsyncPath(tmp_path) / "config.toml"

    await create_configuration_file(configuration_file)

    content = await configuration_file.read_text(encoding="utf-8")
    assert "redactor_file" in content
    with pytest.raises(FileExistsError):
        await create_configuration_file(configuration_file)


@pytest.mark.anyio
async def test_config_init_command_does_not_overwrite_existing_file(tmp_path) -> None:
    """The CLI reports an existing configuration without changing it."""
    configuration_file = tmp_path / "config.toml"
    await AsyncPath(configuration_file).write_text("address = 'https://example.test'\n", encoding="utf-8")

    result = CliRunner().invoke(cli, ["--config", str(configuration_file), "config", "init"])

    assert result.exit_code != 0
    assert await AsyncPath(configuration_file).read_text(encoding="utf-8") == "address = 'https://example.test'\n"


@pytest.mark.anyio
async def test_config_help_hides_only_inapplicable_initialisation(tmp_path) -> None:
    """The config group retains path discovery after configuration exists."""
    configuration_file = tmp_path / "config.toml"
    runner = CliRunner()

    absent = runner.invoke(cli, ["--config", str(configuration_file), "config", "--help"])
    await AsyncPath(configuration_file).write_text('address = "https://example.test"\n', encoding="utf-8")
    existing = runner.invoke(cli, ["--config", str(configuration_file), "config", "--help"])
    path = runner.invoke(cli, ["--config", str(configuration_file), "config", "path"])

    assert absent.exit_code == 0
    assert "init" in absent.output
    assert "path" in absent.output
    assert existing.exit_code == 0
    assert "init" not in existing.output
    assert "path" in existing.output
    assert path.exit_code == 0
    assert path.output.strip() == str(configuration_file)


@pytest.mark.anyio
async def test_nested_help_ignores_invalid_persistent_logging_configuration(tmp_path) -> None:
    """Nested help remains available to diagnose persistent logging configuration."""
    configuration_file = tmp_path / "config.toml"
    await AsyncPath(configuration_file).write_text('log_level = "WARNING"\n', encoding="utf-8")

    result = CliRunner().invoke(cli, ["--config", str(configuration_file), "token", "create", "--help"])

    assert result.exit_code == 0
    assert "Create a new account access token" in result.output
    assert "Unable to initialise persistent logging" not in result.output


@pytest.mark.anyio
async def test_cli_only_log_suppression_does_not_create_a_persistent_handler(tmp_path) -> None:
    """The CLI-only logging switch preserves console output but suppresses file logging."""
    log_file = tmp_path / "auth-guide.log"
    configuration = resolve_configuration(tmp_path / "config.toml", log_file=str(log_file), cli_log=False)

    logger = configure_logging(configuration, cli_only=True)
    logger.info("ordinary message")

    assert not await AsyncPath(log_file).exists()


@pytest.mark.anyio
async def test_file_logging_uses_the_configured_persistent_level_and_formatter(tmp_path) -> None:
    """An explicitly configured persistent handler writes ordinary records only."""
    log_file = tmp_path / "auth-guide.log"
    configuration = resolve_configuration(tmp_path / "config.toml", log_file=str(log_file), log_level="INFO")

    logger = configure_logging(configuration, cli_only=True)
    logger.info("ordinary message")
    for handler in logger.handlers:
        handler.flush()

    assert "ordinary message" in await AsyncPath(log_file).read_text(encoding="utf-8")


@pytest.mark.anyio
async def test_setup_help_exposes_only_explicit_orphan_key_recovery() -> None:
    """Setup documents its narrow recovery switch and no general reset control."""
    result = CliRunner().invoke(cli, ["init", "--help"])

    assert result.exit_code == 0
    assert "--remove-orphan-key" in result.output
    assert "--force" not in result.output


@pytest.mark.anyio
async def test_secret_generating_commands_require_terminal_output() -> None:
    """Generated credentials are never written to a redirected ordinary stream."""
    runner = CliRunner()

    setup = runner.invoke(cli, ["init", "admin@example.com"])
    token = runner.invoke(cli, ["token", "create", "laptop"])

    assert setup.exit_code != 0
    assert "terminal stdout" in setup.output
    assert token.exit_code != 0
    assert "terminal stdout" in token.output


@pytest.mark.anyio
async def test_cli_allows_empty_privilege_lists(monkeypatch) -> None:
    """Account and token creation accept ordinary authenticated access."""
    monkeypatch.setenv("AUTH_GUIDE_TOKEN", "agt_example")
    environment = dict(os.environ)
    account = await anyio.run_process(
        ["uv", "run", "auth-guide", "--address", "https://127.0.0.1:1", "account", "create", "member@example.com"],
        input=b"too short\ntoo short\ninitial password\ninitial password\n",
        env=environment,
        check=False,
    )
    token = await anyio.run_process(
        ["uv", "run", "auth-guide", "token", "create", "laptop"],
        env=environment,
        check=False,
    )

    assert account.returncode != 0
    assert b"Missing option '--grant'" not in account.stderr
    assert b"Password must contain at least 12 characters" in account.stderr
    assert b"Could not reach the management API" in account.stderr
    assert token.returncode != 0
    assert b"Missing option '--scope'" not in token.stderr
    assert b"terminal stdout" in token.stderr


@pytest.mark.anyio
async def test_authenticated_command_requires_an_explicit_operator_bearer() -> None:
    """A command fails locally rather than issuing an unauthenticated request."""
    result = CliRunner().invoke(cli, ["account", "me"])

    assert result.exit_code != 0
    assert "AUTH_GUIDE_TOKEN or --token is required" in result.output


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("command", "prompt"),
    [
        (["account", "create", "member@example.com"], "Initial password"),
        (["account", "password"], "New password"),
        (["account", "reset-password", "member@example.com"], "New password"),
    ],
)
async def test_password_commands_authenticate_before_prompting(command: list[str], prompt: str) -> None:
    """Password entry is not requested before a required operator bearer exists."""
    result = CliRunner().invoke(cli, command)

    assert result.exit_code != 0
    assert "AUTH_GUIDE_TOKEN or --token is required" in result.output
    assert prompt not in result.output


@pytest.mark.anyio
async def test_account_creation_rejects_naive_expiry_before_prompting(monkeypatch) -> None:
    """A locally invalid expiry does not collect an initial password."""
    monkeypatch.setenv("AUTH_GUIDE_TOKEN", "agt_example")

    result = CliRunner().invoke(
        cli,
        ["account", "create", "member@example.com", "--expires-at", "2030-01-01T00:00:00"],
    )

    assert result.exit_code != 0
    assert "Account expiry must include a timezone" in result.output
    assert "Initial password" not in result.output


@pytest.mark.anyio
async def test_empty_grant_replacement_requires_explicit_flag() -> None:
    """Clearing every grant must be requested with the documented explicit flag."""
    result = CliRunner().invoke(cli, ["grant", "set", "member@example.com"])
    help_result = CliRunner().invoke(cli, ["grant", "set", "--help"])

    assert result.exit_code != 0
    assert "Clearing every grant requires --clear" in result.output
    assert "Usage:" not in result.output
    assert help_result.exit_code == 0
    assert "omitted grants clear it with --clear" in help_result.output


@pytest.mark.anyio
@pytest.mark.parametrize(
    "command", [["token", "relabel", "../accounts/example", "new label"], ["token", "revoke", "../accounts/example"]]
)
async def test_token_commands_reject_non_uuid_record_identifiers(command: list[str]) -> None:
    """Token operations do not permit path segments in record identifiers."""
    result = CliRunner().invoke(cli, command)

    assert result.exit_code != 0
    assert "Token identifier must be a UUID" in result.output
    assert "Usage:" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.anyio
async def test_cli_uses_only_the_trusted_https_management_api(tmp_path) -> None:
    """The installed CLI manages a disposable provider without database access."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    async with PlatformSecretProvider("cli-api-test", MemoryKeyring()) as secrets:
        async with LocalCertificateAuthority(AsyncPath(tmp_path) / "tls", secrets) as authority:
            await authority.initialise()
            root_certificate = AsyncPath(tmp_path) / "provider-root.pem"
            await root_certificate.write_text(await authority.get_root_certificate(), encoding="utf-8")
            store = AccountStore(AsyncPath(tmp_path) / "accounts", secrets)
            server = await create_management_server(
                create_management_application(store), authority, host="127.0.0.1", port=port
            )
            serving = asyncio.create_task(server.serve(sockets=[listener]))
            while not server.started:
                await asyncio.sleep(0)
            try:
                trusted_context = ssl.create_default_context(cadata=await authority.get_root_certificate())
                base_url = f"https://localhost:{port}"
                async with httpx.AsyncClient(verify=trusted_context) as client:
                    setup = await client.post(f"{base_url}/v1/setup", json={"email": "admin@example.com"})
                assert setup.status_code == 201
                bearer = setup.json()["token"]

                environment = dict(os.environ)
                environment.update(
                    {
                        "AUTH_GUIDE_TOKEN": bearer,
                        "SSL_CERT_FILE": str(root_certificate),
                    }
                )
                own_account = await anyio.run_process(
                    ["uv", "run", "auth-guide", "--address", base_url, "account", "me"],
                    env=environment,
                    check=False,
                )
                created_account = await anyio.run_process(
                    [
                        "uv",
                        "run",
                        "auth-guide",
                        "--address",
                        base_url,
                        "account",
                        "create",
                        "member@example.com",
                        "--grant",
                        "accounts:read",
                    ],
                    input=b"initial password\ninitial password\n",
                    env=environment,
                    check=False,
                )
                cleared_grants = await anyio.run_process(
                    [
                        "uv",
                        "run",
                        "auth-guide",
                        "--address",
                        base_url,
                        "grant",
                        "set",
                        "member@example.com",
                        "--clear",
                    ],
                    env=environment,
                    check=False,
                )
                read_account = await anyio.run_process(
                    ["uv", "run", "auth-guide", "--address", base_url, "account", "show", "member@example.com"],
                    env=environment,
                    check=False,
                )
                member = await AccountRecord.get(email="member@example.com")
                padded_uuid = await anyio.run_process(
                    [
                        "uv",
                        "run",
                        "auth-guide",
                        "--address",
                        base_url,
                        "account",
                        "show",
                        f" {member.id} ",
                    ],
                    env=environment,
                    check=False,
                )
                untrusted_environment = dict(environment)
                untrusted_environment.pop("SSL_CERT_FILE")
                untrusted = await anyio.run_process(
                    ["uv", "run", "auth-guide", "--address", base_url, "account", "me"],
                    env=untrusted_environment,
                    check=False,
                )
                unauthenticated_environment = dict(environment)
                unauthenticated_environment.pop("AUTH_GUIDE_TOKEN")
                unauthenticated = await anyio.run_process(
                    ["uv", "run", "auth-guide", "--address", base_url, "account", "me"],
                    env=unauthenticated_environment,
                    check=False,
                )
                issued_limited = await generate_account_token()
                administrator = await AccountRecord.get(email="admin@example.com")
                await AccountTokenRecord.create(
                    account=administrator,
                    label="limited",
                    verifier=issued_limited.verifier,
                    scopes=[],
                )
                limited_environment = dict(environment)
                limited_environment["AUTH_GUIDE_TOKEN"] = issued_limited.raw_value
                forbidden = await anyio.run_process(
                    ["uv", "run", "auth-guide", "--address", base_url, "account", "list"],
                    env=limited_environment,
                    check=False,
                )
                invalid_password = await anyio.run_process(
                    ["uv", "run", "auth-guide", "--address", base_url, "account", "password"],
                    input=b"too short\ntoo short\n",
                    env=environment,
                    check=False,
                )

                assert own_account.returncode == 0
                assert created_account.returncode == 0
                assert cleared_grants.returncode == 0
                assert read_account.returncode == 0
                assert padded_uuid.returncode == 0
                assert b"admin@example.com" in own_account.stdout
                assert b"member@example.com" in created_account.stdout
                assert b"member@example.com" in read_account.stdout
                assert b"member@example.com" in padded_uuid.stdout
                assert (await AccountRecord.get(email="member@example.com")).grants == []
                assert bearer.encode() not in own_account.stdout + own_account.stderr
                assert b"initial password" not in created_account.stdout + created_account.stderr
                assert untrusted.returncode != 0
                assert unauthenticated.returncode != 0
                assert forbidden.returncode != 0
                assert invalid_password.returncode != 0
                assert bearer.encode() not in untrusted.stdout + untrusted.stderr
                assert issued_limited.raw_value.encode() not in forbidden.stdout + forbidden.stderr
                assert b"too short" not in invalid_password.stdout + invalid_password.stderr
                assert (await AccountRecord.get(email="admin@example.com")).must_change_password is True
            finally:
                server.should_exit = True
                await serving
                await store.aclose()


@pytest.mark.anyio
async def test_current_log_redactor_is_an_explicit_pass_through() -> None:
    """The deferred rules-file policy leaves ordinary messages unchanged for now."""
    record = logging.LogRecord("auth_guide", logging.INFO, __file__, 1, "ordinary message", (), None)

    assert RedactingFormatter("%(message)s").format(record) == "ordinary message"
