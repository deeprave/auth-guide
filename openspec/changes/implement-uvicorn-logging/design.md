# Design

## Context

See `proposal.md` for motivation. `configure_logging()` currently manages only
the `auth_guide` logger. Uvicorn is constructed without an explicit logging
configuration and therefore applies its own defaults, while access logging is
disabled. The management API uses email selectors in query strings and UUID
identifiers in both query strings and path segments.

## Goals / Non-Goals

**Goals:**

- Give Uvicorn server, error, and access records one provider-owned logging
  lifecycle.
- Enable useful HTTP access records without retaining account identifiers or
  arbitrary query values.
- Make foreground access output readable without changing the normal console
  format or persistent log format.
- Preserve handler replacement and close semantics across SIGHUP rebuilds.

**Non-Goals:**

- Changing API routes, account selectors, logger configuration options, or the
  deferred user-supplied redactor-file feature.
- Logging request headers, request bodies, bearer credentials, passwords, or
  issued token values.
- Defining a general-purpose PII classification system.

## Decisions

### Provider-owned Uvicorn logger bindings

The runtime will disable Uvicorn's default logging configuration and bind
`uvicorn`, `uvicorn.error`, and `uvicorn.access` to provider-managed handlers
after the provider logging configuration is established. This lets existing
console, file, syslog, level, redaction, and handler-replacement policy apply
to Uvicorn records.

Copying mcp-guide's `log_config` dictionary is not suitable: mcp-guide directs
all Uvicorn output to a dedicated stream handler, whereas auth-guide must share
its optional persistent handlers and retain its daemon/foreground distinction.

### Access-target sanitisation before formatting

An access-log filter will sanitise Uvicorn's request-target data before any
handler formats it. It will parse rather than substring-replace URLs, retaining
the path, query parameter names, ordering, and duplicates while replacing
values as follows:

- `email` and `account_email` values are parsed as addresses. The local part
  and registrable domain label retain their first and last character (or their
  sole character) with a fixed `***` mask between them; the public suffix is
  retained. For example, `john.smith@hobnobs.com` becomes
  `j***h@h***s.com`.
- UUID-like values in a path segment or query value retain their first and last
  four characters, with every intervening character replaced by `*`.
- Every other query value becomes `***` unless a future requirement explicitly
  defines it as safe to retain.

The policy is allowlist-based for retained query values. It prevents future
selector parameters from leaking merely because they were not added to a
blocklist.

### Separate foreground access handler

Foreground mode will attach a dedicated Rich access handler to
`uvicorn.access`, using a concise sanitised method/target/status presentation
without timestamp or level columns. Uvicorn server and error records keep the
ordinary Rich provider handler. Persistent file and syslog handlers receive all
three Uvicorn logger categories through the standard timestamped redacting
formatter.

Detached mode will not attach a console access handler. Its Uvicorn records
flow only to configured persistent handlers, consistent with daemon logging
policy.

### Reconfiguration ownership

The provider logging module will remove and close all handlers it owns from the
provider and Uvicorn logger namespaces before rebuilding them. This prevents
default Uvicorn handlers, duplicate records, and closed shared handlers from
surviving a SIGHUP generation change.

## Risks / Trade-offs

- [Access records can be high volume] → Access logging follows the configured
  console and persistent levels, and retains only method, sanitised target, and
  response status.
- [Malformed request-target data may not parse] → Emit a fixed sanitised target
  marker rather than the raw value.
- [Shared logger state is changed during rebuild] → Replace provider-owned
  bindings atomically at the logging boundary and test one-record behaviour
  over repeated rebuilds.

## Migration Plan

1. Deploy with the existing logging configuration values; no new configuration
   is required.
2. Verify foreground access presentation and persistent server/access records
   against a disposable TLS provider.
3. If a deployment needs rollback, restore the prior release; configuration
   files remain compatible.

