# Tasks

## 1. Establish one process-wide redaction boundary

- [ ] 1.1 Replace the pass-through formatter hook with an idempotent wrapper
  around the current standard-library `LogRecordFactory`; verify repeated
  logging configuration does not stack wrappers and a non-propagating handler
  receives masked recognised values.
- [ ] 1.2 Sanitise ordinary message arguments and standard logged exception
  text before formatter execution while preserving useful non-secret message
  structure; verify independent handlers cannot format raw recognised tokens,
  bearer credentials, email addresses, or UUIDs.
- [ ] 1.3 Remove the no-op formatter and Uvicorn-only filter path, move shared
  target masking into the redaction boundary, and remove `redactor_file` from
  generated configuration; verify legacy TOML values remain harmless and the
  existing foreground and persistent presentation is unchanged.

## 2. Sanitise observed dependency diagnostics structurally

- [ ] 2.1 Apply the existing request-target masking to Uvicorn's observed
  five-item access-record shape at record creation; verify a separately owned,
  non-propagating Uvicorn access handler retains method, route, status, and
  query names without raw selector or credential values.
- [ ] 2.2 Sanitise HTTPX's observed outbound request-summary records,
  including the administration CLI's management-API traffic; verify method,
  authority, path, status, and query names remain useful while query values
  are masked.
- [ ] 2.3 Sanitise Tortoise database-client parameterised-query records by
  retaining query text and replacing bound values as a unit; verify an
  independently handled diagnostic cannot disclose an account selector,
  password verifier, or token verifier.
- [ ] 2.4 Apply conservative generic masking to other normal logging records
  such as HTTPcore, keyring, and Uvicorn error/ASGI diagnostics; verify known
  credential and selector patterns are masked without enabling dependency
  verbosity as a side effect.

## 3. Validate the provider boundary and document its limits

- [ ] 3.1 Exercise a trusted live HTTPS provider request with Uvicorn access
  logging and confirm the provider's normal lifecycle, foreground, and
  persistent logging behaviour remains intact without raw sensitive values.
- [ ] 3.2 Document supported structural dependency patterns and the deliberate
  limitations for arbitrary PII, manually constructed records, handler-specific
  `extra` values, pre-boundary records, and unparameterised SQL.
- [ ] 3.3 Run the full project quality gate, strict OpenSpec validation, and a
  focused review of the process-wide logging boundary; record any unrelated
  dependency-advisory outcome separately from this change.
