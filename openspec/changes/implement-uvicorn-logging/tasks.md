# Tasks

## 1. Provider-owned Uvicorn logging

- [x] 1.1 Extend the logging boundary to replace and close provider-owned Uvicorn logger bindings alongside auth-guide handlers; verify repeated configuration writes each Uvicorn server record exactly once.
- [x] 1.2 Construct the provider HTTP server without Uvicorn's default logging configuration and with access logging enabled; verify server-operation and access records use the configured provider handlers.

## 2. Sanitised HTTP access records

- [x] 2.1 Add deterministic request-target sanitisation before access formatting: structurally mask email selectors, mask UUID-like path and query identifiers except for their first and last four characters, and replace unapproved query values with `***`; verify representative and malformed targets never emit raw input.
- [x] 2.2 Add a dedicated concise Rich foreground access formatter and bind it only for foreground operation; verify detached operation sends sanitised access records exclusively to configured persistent handlers.

## 3. Runtime integration and regression coverage

- [x] 3.1 Exercise trusted HTTPS management requests against a disposable provider and verify emitted access records retain method, route, and query names while masking email and UUID selectors.
- [x] 3.2 Exercise a SIGHUP server rebuild with persistent logging enabled and verify Uvicorn server/access records remain sanitised and are not duplicated.
## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.

