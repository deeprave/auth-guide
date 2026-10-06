# auth-guide

[![Build](https://img.shields.io/github/actions/workflow/status/deeprave/auth-guide/test.yaml?branch=main&label=build&logo=github)](https://github.com/deeprave/auth-guide/actions/workflows/test.yaml)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen.svg)](https://github.com/deeprave/auth-guide)
[![PyPI version](https://img.shields.io/pypi/v/auth-guide.svg?logo=pypi&logoColor=white)](https://pypi.org/project/auth-guide/)
[![PyPI downloads](https://img.shields.io/pypi/dm/auth-guide.svg?logo=pypi&logoColor=white)](https://pypi.org/project/auth-guide/)
[![Python versions](https://img.shields.io/pypi/pyversions/auth-guide.svg?logo=python&logoColor=white)](https://pypi.org/project/auth-guide/)

Reference OIDC provider service and administration CLI for the future
`auth-ref-oidc` integration in mcp-guide.

This repository contains the Python project scaffold. The reference provider,
account schema, and OIDC endpoints remain future changes. Persistent account
data will use an encrypted database.

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
