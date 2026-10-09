# auth-guide

[![Build](https://img.shields.io/github/actions/workflow/status/deeprave/auth-guide/test.yaml?branch=main&label=build&logo=github)](https://github.com/deeprave/auth-guide/actions/workflows/test.yaml)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen.svg)](https://github.com/deeprave/auth-guide)
[![PyPI version](https://img.shields.io/pypi/v/auth-guide.svg?logo=pypi&logoColor=white)](https://pypi.org/project/auth-guide/)
[![PyPI downloads](https://img.shields.io/pypi/dm/auth-guide.svg?logo=pypi&logoColor=white)](https://pypi.org/project/auth-guide/)
[![Python versions](https://img.shields.io/pypi/pyversions/auth-guide.svg?logo=python&logoColor=white)](https://pypi.org/project/auth-guide/)

auth-guide is the reference auth-provider: a working example OIDC provider and
provider API for use with mcp-guide. Account management, authentication, token
issuance, and the provider API are its core purpose—not speculative platform
infrastructure.

Requires Python 3.12 or later.

Account schema and OIDC endpoint work is delivered through separately scoped
changes. Persistent account data uses an encrypted database.

## Local TLS authority

The library provides a provider-owned local certificate authority for the
reference service. Initialise it once before any other certificate operation;
the CA and server private keys remain in the platform secret store, while
public certificate lifecycle metadata is kept under
`~/.config/mcp-guide/auth/` by default. The future administration CLI will
provide the supported initialisation, rotation, and trust-management commands.

System trust changes are explicit privileged operations. Debian-family systems
use `update-ca-certificates`; Red Hat-family systems use `update-ca-trust` and
the p11-kit anchor directory. The latter is supported by its platform facade,
but native Red Hat validation remains an operator/CI responsibility until a
Red Hat execution environment is added. macOS uses the System Keychain with an
SSL-only trust setting. No arbitrary JDK or Amazon Corretto trust store is
modified.

## Platform secret store

Provider-owned secret values are held outside configuration and database files.
The runtime asks `keyring` for the sensible backend on the current operating
system: normally macOS Keychain on macOS and Freedesktop Secret Service on
Linux. Linux deployments need a running D-Bus session and a
Secret-Service-compatible keyring, such as GNOME Keyring.

Operators can configure a compatible non-default backend using the standard
`keyring` configuration mechanism. That choice is part of the host's security
boundary; auth-guide neither substitutes a fallback nor attempts to classify
the configured backend's storage security.

The GitHub Actions Linux test job starts an ephemeral GNOME Keyring session.
On macOS, the corresponding Keychain integration test runs locally; platform
specific tests are skipped on other operating systems.

## Licence

MIT. See [LICENSE](LICENSE).
