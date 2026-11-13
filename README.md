# auth-guide

[![Build](https://img.shields.io/github/actions/workflow/status/deeprave/auth-guide/test.yaml?branch=main&label=build&logo=github)](https://github.com/deeprave/auth-guide/actions/workflows/test.yaml)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen.svg)](https://github.com/deeprave/auth-guide)
[![PyPI version](https://img.shields.io/pypi/v/auth-guide.svg?logo=pypi&logoColor=white)](https://pypi.org/project/auth-guide/)
[![PyPI downloads](https://img.shields.io/pypi/dm/auth-guide.svg?logo=pypi&logoColor=white)](https://pypi.org/project/auth-guide/)
[![Python versions](https://img.shields.io/pypi/pyversions/auth-guide.svg?logo=python&logoColor=white)](https://pypi.org/project/auth-guide/)

auth-guide is a **reference authentication provider** for [mcp-guide](https://pypi.org/project/mcp-guide/) version 2.0.0 and later, used only when running the MCP in https mode.

This implementation is a local account and bearer-token service supporting Guide authentication decisions, and an HTTPS management API with an administration CLI. Persistent account data uses an encrypted SQLite database. This reference implementation does not support mTLS.

auth-guide requires Python 3.12 or later.

## Local TLS authority

The library provides a provider-owned local certificate authority for the reference service. Initialise it once before any other certificate operation; the CA and server private keys remain in the platform secret store, while public certificate lifecycle metadata is kept under the configuration directory, `~/.config/mcp-guide/auth/` by default. The administration CLI provides the supported initialisation and trust-management commands.

System trust changes are explicit privileged operations. Debian-family systems use `update-ca-certificates`; Red Hat-family systems use `update-ca-trust` and the p11-kit anchor directory. The latter is supported by its platform facade, but native Red Hat validation remains an operator/CI responsibility. macOS uses the System Keychain with an SSL-only trust setting. Linux systems that use Java-style trust stores such as Amazon Corretto require manual integration of the generated CA certificate.

## Platform secret store

Provider-owned secret values are held outside configuration and database files. The runtime asks [`keyring`](https://pypi.org/project/keyring/) for the sensible backend on the current operating system: normally macOS Keychain on macOS and Freedesktop Secret Service on Linux. Linux deployments need a running D-Bus session and a Secret-Service-compatible keyring, such as GNOME Keyring.

Operators can configure a compatible non-default backend using the standard `keyring` configuration mechanism. That choice is part of the host's security boundary; auth-guide neither substitutes a fallback nor attempts to classify the configured backend's storage security.

## Provider storage namespaces

Use `--namespace NAME` to isolate one provider's platform-secret entries, encrypted database, certificate metadata, and server lifecycle files from another provider using the same configuration directory. `AG_NAMESPACE` supplies the environment override; an explicit `--namespace` takes precedence. A namespace must contain only ASCII letters, numbers, hyphens, and underscores. The default is `auth-guide`.

Use `--configdir DIRECTORY` or `AG_CONFIGDIR` to select the provider storage root. The precedence is `--configdir`, `AG_CONFIGDIR`, the parent directory of an explicit `--config` or `AG_CONFIG` file, then the platform default. An explicit configuration file remains selected when a storage-root override is present; otherwise auth-guide uses `{configdir}/{namespace}-config.toml`.

Within the selected storage root, each namespace uses `{namespace}.lifecycle.lock`, `{namespace}.sqlite3`, `{namespace}.pid`, `{namespace}.meta.json`, `{namespace}-certificates.json`, and `{namespace}-config.toml`. This is a breaking filename change: manually rename existing `auth-guide.lifecycle.lock`, `auth-guide.sqlite3`, `auth-guide.pid`, `auth-guide.meta.json`, `certificates.json`, and `config.toml` before upgrading. Legacy filenames are not read.

## Running the local provider

The local HTTPS provider is operated with `auth-guide server`. First create any optional configuration scaffold, initialise the local certificate authority, and create the first administrator. `init` displays the initial password and bearer token once, so run it from a terminal and store those credentials safely.

```console
$ auth-guide config init
$ auth-guide ca init
$ auth-guide init admin@example.com
```

Start the provider as a detached local process, then inspect its structured JSON status:

```console
$ auth-guide server start
$ auth-guide server status
```

`server start` waits for HTTPS readiness for up to 30 seconds. It does not create or migrate a certificate authority, encrypted account database, or platform-secret-store key; complete the explicit setup above first. Use `--listen` (or `-L`) only with `server start` or `server foreground` to override the configured listener for that invocation.

For development or external supervision, run the service in the foreground:

```console
$ auth-guide server foreground --listen https://localhost:8443
```

The lifecycle commands use state files that reside in the configuration directory. `server restart` rebuilds the running service in place after rereading its TOML configuration, while retaining its PID.

`server stop` requests graceful shutdown and never escalates to SIGKILL automatically.

```console
$ auth-guide server restart
$ auth-guide server stop
```

## API reference

This reference implementation exposes a bearer-authentication decision endpoint and a separate HTTPS management API. Alternative providers can implement the same contracts without using this database, CLI, or internal code.

Authentication and management endpoints require an `Authorization: Bearer <token>` header and return JSON. UUID values are strings; timestamps are ISO 8601 strings. An `Account` response contains `id`, `email`, `grants`, `created_at`, `expires_at`, `full_name`, and `must_change_password`. A `Token` response contains `id`, `account_id`, `label`, `scopes`, and `created_at`. Successful deletion returns `204 No Content`.

`GET /openapi.json` does not require bearer authentication and returns the machine-readable OpenAPI description of the authentication and management endpoints. Interactive API documentation is disabled.

### Guide authentication decision

| Method | Path | Request | Response |
| --- | --- | --- | --- |
| `POST` | `/v1/authenticate` | No body | `200` `{"account_id": "UUID", "scopes": ["admin"]}`; `scopes` is empty for a non-administrator. |

### Management API

Management operations use the same bearer authentication. Account operations that target another account require the appropriate account-management grant; token operations for another account require `tokens:manage`.

| Method | Path | Request parameters or JSON body | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/accounts/me` | None | `200` `Account` |
| `PATCH` | `/v1/accounts/me` | JSON: optional `email`, `full_name` | `200` `Account` |
| `POST` | `/v1/accounts/me/password` | JSON: `password` (minimum 12 characters) | `200` `Account` |
| `POST` | `/v1/accounts/me/close` | None | `200` `Account` with an immediate expiry |
| `GET` | `/v1/accounts` | Optional query: `email` | `200` `Account[]`, or one `Account` when `email` is supplied |
| `POST` | `/v1/accounts` | JSON: `email`, `password`, `grants`; optional `full_name`, timezone-aware `expires_at` | `201` `Account` |
| `GET` | `/v1/accounts/{account_id}` | Path: `account_id` | `200` `Account` |
| `PATCH` | `/v1/accounts/{account_id}` | Path: `account_id`; JSON: one complete `grants` list or `add_grants`/`remove_grants`, optional `reactivate` | `200` `Account` |
| `DELETE` | `/v1/accounts/{account_id}` | Path: `account_id` | `204` |
| `PATCH` | `/v1/accounts?email={email}` | Query: `email`; JSON: as for the UUID-targeted `PATCH` | `200` `Account` |
| `POST` | `/v1/accounts/password?email={email}` | Query: `email`; JSON: `password` (minimum 12 characters) | `200` `Account` |
| `DELETE` | `/v1/accounts?email={email}` | Query: `email` | `204` |
| `POST` | `/v1/accounts/{account_id}/password` | Path: `account_id`; JSON: `password` (minimum 12 characters) | `200` `Account` |
| `GET` | `/v1/tokens` | Optional query: exactly one of `account_id`, `account_email` | `200` `Token[]` |
| `POST` | `/v1/tokens` | JSON: `label`, `scopes`; optional exactly one of `account_id`, `account_email` | `201` `Token` plus once-only `token` bearer string |
| `PATCH` | `/v1/tokens/{token_id}` | Path: `token_id`; JSON: `label` | `200` `Token` |
| `DELETE` | `/v1/tokens/{token_id}` | Path: `token_id` | `204` |

## CLI reference

The administration CLI is an HTTPS API client, not a direct database interface. Supply an operator bearer through `AUTH_GUIDE_TOKEN` or `--token`; use `--address`/`-A` to select the provider address.

| Commands | Management operation |
| --- | --- |
| `account list`, `account show ACCOUNT`, `account me` | List accounts, retrieve an account by UUID or email, or retrieve the authenticated account. |
| `account create EMAIL`, `account delete ACCOUNT` | Create or permanently delete an account; creation prompts for the initial password. |
| `account update`, `account reactivate ACCOUNT`, `account password`, `account reset-password ACCOUNT`, `account close` | Update the authenticated profile, reactivate an account, replace a password, or close the authenticated account. Password commands use hidden prompts. |
| `grant list ACCOUNT`, `grant set ACCOUNT`, `grant add ACCOUNT GRANT`, `grant remove ACCOUNT GRANT` | Read, replace, add, or remove an account's grants. Replacing with no grants requires `--clear`. |
| `token create LABEL`, `token list`, `token relabel TOKEN_ID LABEL`, `token revoke TOKEN_ID` | Create, list, relabel, or revoke bearer tokens. Token creation displays the new bearer value once. |

Run `auth-guide --help` or `auth-guide COMMAND --help` for command-specific options, including configuration, certificate-authority, and server lifecycle commands.

## License

MIT. See [LICENSE](LICENSE).
