# Tasks

## 1. Provider runtime ownership

- [ ] 1.1 Build the asynchronous provider runtime that owns TLS, account-store startup and shutdown, migration readiness, and HTTPS serving; verify start-up failure closes every owned component
- [ ] 1.2 Add foreground CLI execution of that runtime and verify trusted HTTPS management access and clean signal-driven shutdown

## 2. Background lifecycle

- [ ] 2.1 Implement POSIX background start with bounded readiness reporting, controlled output, and configuration-root PID state; verify the command returns only after HTTPS readiness
- [ ] 2.2 Implement PID identity validation, stale-state cleanup, duplicate-start rejection, status, and safe stop; verify an unrelated live PID is never signalled

## 3. End-to-end validation

- [ ] 3.1 Exercise start, status, duplicate start, stop, stale PID recovery, and foreground operation against a disposable provider configuration; verify no credentials appear in output or logs
