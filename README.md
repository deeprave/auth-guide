# auth-guide

[![Build](https://img.shields.io/github/actions/workflow/status/deeprave/auth-guide/test.yaml?branch=main&label=build&logo=github)](https://github.com/deeprave/auth-guide/actions/workflows/test.yaml)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen.svg)](https://github.com/deeprave/auth-guide)
[![PyPI version](https://img.shields.io/pypi/v/auth-guide.svg?logo=pypi&logoColor=white)](https://pypi.org/project/auth-guide/)
[![PyPI downloads](https://img.shields.io/pypi/dm/auth-guide.svg?logo=pypi&logoColor=white)](https://pypi.org/project/auth-guide/)
[![Python versions](https://img.shields.io/pypi/pyversions/auth-guide.svg?logo=python&logoColor=white)](https://pypi.org/project/auth-guide/)

auth-guide is a local account and bearer-token service for mcp-guide. It provides encrypted account persistence, Guide authentication decisions, and an HTTPS management API with an administration CLI. It is not an OpenID Connect provider.

Requires Python 3.12 or later.

Persistent account data uses an encrypted database.

## Local TLS authority

The library provides a provider-owned local certificate authority for the reference service. Initialise it once before any other certificate operation; the CA and server private keys remain in the platform secret store, while public certificate lifecycle metadata is kept under `~/.config/mcp-guide/auth/` by default. The administration CLI provides the supported initialisation and trust-management commands.

System trust changes are explicit privileged operations. Debian-family systems use `update-ca-certificates`; Red Hat-family systems use `update-ca-trust` and the p11-kit anchor directory. The latter is supported by its platform facade, but native Red Hat validation remains an operator/CI responsibility until a Red Hat execution environment is added. macOS uses the System Keychain with an SSL-only trust setting.

## Platform secret store

Provider-owned secret values are held outside configuration and database files. The runtime asks [`keyring`](https://pypi.org/project/keyring/) for the sensible backend on the current operating system: normally macOS Keychain on macOS and Freedesktop Secret Service on Linux. Linux deployments need a running D-Bus session and a Secret-Service-compatible keyring, such as GNOME Keyring.

Operators can configure a compatible non-default backend using the standard `keyring` configuration mechanism. That choice is part of the host's security boundary; auth-guide neither substitutes a fallback nor attempts to classify the configured backend's storage security.

The GitHub Actions Linux test job starts an ephemeral GNOME Keyring session. On macOS, the corresponding Keychain integration test runs locally; platform specific tests are skipped on other operating systems.

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

The lifecycle commands use state files beside the selected configuration file. `server restart` rebuilds the running service in place after rereading its TOML configuration, while retaining its PID. `server stop` requests graceful shutdown and never escalates to SIGKILL automatically.

```console
$ auth-guide server restart
$ auth-guide server stop
```

## Licence

MIT. See [LICENSE](LICENSE).
