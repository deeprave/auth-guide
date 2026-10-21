# Design

## Context

See `proposal.md` for motivation and the delta specification for the required
observable behaviour. The current formatter-level hook is a pass-through, so
it only observes records that reach auth-guide-owned handlers. The current
Uvicorn access filter is useful structural logic but is too late to protect a
separate dependency-owned handler.

Inspection of installed runtime dependencies establishes the concrete targets:

- the administration CLI is the only production caller of HTTPX; HTTPX logs an
  outbound method and complete URL at INFO;
- Uvicorn logs access records as a five-item tuple containing the raw request
  target;
- Tortoise's SQLite client logs parameterised query text and bound values via
  `tortoise.db_client` at DEBUG; tortoise-sqlcipher uses that Tortoise client
  boundary;
- HTTPcore traces, keyring diagnostics, and Uvicorn error/ASGI messages remain
  ordinary standard-library logging records.

## Goals / Non-Goals

**Goals:**

- Sanitise standard logging records before propagation or handler dispatch.
- Retain useful structure for the dependency patterns actually used here.
- Remove the misleading inert redactor configuration and formatter layer.
- Preserve the existing foreground and persistent logging presentation.

**Non-Goals:**

- Promise detection of arbitrary personally identifiable information.
- Enable dependency DEBUG logging as a side effect of auth-guide verbosity.
- Parse arbitrary SQL dialects or unparameterised application SQL.
- Intercept records emitted before auth-guide establishes its logging boundary,
  records manually constructed outside normal logging APIs, or arbitrary
  sensitive values placed in third-party handler-specific `extra` fields.

## Decisions

### Chain one process-wide record factory

Install an idempotent wrapper around the currently installed
`logging.LogRecordFactory` while establishing safe console logging. The wrapper
first delegates to the prior factory, then sanitises the completed record before
any logger's propagation or handlers execute. Reconfiguration detects the
wrapper and does not stack it.

This is preferred to a root logger filter because ancestor logger filters do
not receive propagated child records. It is also preferred to attaching filters
only to provider handlers because dependency handlers with `propagate = False`
would bypass them. A process-wide hook is appropriate because auth-guide is a
standalone CLI/provider process.

### Use structural rules before generic text masking

The record factory will recognise exact dependency logger/message shapes:

- `uvicorn.access` five-item access tuples: replace the request target with the
  existing route/query structural sanitisation before any formatter receives it;
- `httpx` request-summary records: retain method, authority, path, and status,
  but parse and sanitise query values in the URL;
- `tortoise.db_client` parameterised-query records: preserve the SQL text and
  replace bound values as a unit. This matches Tortoise's reliable
  `query, values` logging convention without pretending to parse SQL.

All other records render through a conservative generic masker for auth-guide
tokens, Bearer credentials, emails, UUIDs, and recognised URLs. Sanitised text
replaces the original message arguments so downstream handlers cannot format
their raw values. Logged exception text is rendered and sanitised once before
handler formatters run.

The existing Uvicorn access filter and pass-through `RedactingFormatter` will
be removed because the record factory replaces their protection role. The
existing HTTP target parsing helpers move to the shared redaction module rather
than being reimplemented.

### Keep dependency verbosity independent

Auth-guide's configured verbosity continues to govern only its owned logging
namespaces. The change does not lower effective levels for HTTPX, HTTPcore,
Tortoise, keyring, or Uvicorn ASGI diagnostics. If a deployer or future code
enables one, the record factory still sanitises its records.

### Sequence after the current Uvicorn logging change

`implement-uvicorn-logging` currently introduces the access-target helpers this
change relocates. Complete, merge, sync, and archive that change first; then
apply this change as its focused successor. This avoids competing edits to the
same logging boundary and specification requirement.

## Risks / Trade-offs

- [A prior factory has application-specific behaviour] → delegate to it before
  sanitising and install exactly one wrapper.
- [A dependency changes its logging message shape] → unknown records still pass
  through generic masking; add an explicit structural rule only with observed
  dependency evidence and tests.
- [Exception rendering loses original `exc_info` semantics] → retain the normal
  formatted traceback text after sanitisation; do not expose raw exception
  arguments to a later formatter.
- [A direct SQL string embeds secrets] → Tortoise bound values are protected,
  but deployers must not embed secrets in unparameterised SQL; this is outside
  reliable generic SQL parsing.
- [The hook affects unrelated in-process handlers] → auth-guide owns the CLI
  and provider process; the cross-cutting protection is intentional.

## Migration Plan

1. Complete and archive `implement-uvicorn-logging` first.
2. Deploy without configuration changes; legacy `redactor_file` values remain
   accepted and ignored.
3. Verify provider, Uvicorn, HTTPX, and Tortoise diagnostics with both owned
   and non-propagating test handlers.
4. Roll back to the prior release if a third-party logger relies on raw message
   arguments; no database or API migration is required.
