# Proposal

## Why

The provider's Uvicorn runtime currently installs its default logging
configuration, bypassing auth-guide's configured logging policy and leaving
HTTP access logging disabled. Enabling ordinary Uvicorn access logs unchanged
would disclose account email addresses and account UUID selectors present in
management-API query strings.

## What Changes

- Route Uvicorn server-operation and access records through auth-guide's
  managed logging configuration rather than Uvicorn defaults.
- Enable provider HTTP access logging with a distinct, concise foreground
  console presentation while retaining the configured persistent formatter for
  file and syslog output.
- Add deterministic access-target masking: query parameter names remain
  visible, while email values are structurally masked and account UUID values
  retain only their first and last four characters.
- Redact all other query values by default unless a future requirement
  explicitly approves a non-sensitive operational value for logging.
- Ensure logger reconfiguration across in-process server rebuilds neither
  duplicates handlers nor restores Uvicorn's defaults.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `provider-administration-cli`: extend the provider's secret-safe logging
  contract to cover Uvicorn server and access logs, including safe query-value
  masking and foreground access formatting.

## Impact

- `src/auth_guide/cli/logging.py` will own the Uvicorn logger integration and
  access-target sanitisation.
- `src/auth_guide/management_api.py` will stop selecting Uvicorn's default
  logger configuration and enable access logging through the provider policy.
- `src/auth_guide/server/runtime.py` will configure Uvicorn logging for each
  server generation.
- Logging and live HTTPS tests will verify redaction, handler ownership, and
  foreground versus detached output.
