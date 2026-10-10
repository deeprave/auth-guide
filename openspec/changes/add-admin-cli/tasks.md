# Tasks

## 1. API client

- [ ] 1.1 Implement local-CA-trusting authenticated API client commands for bootstrap, account lifecycle, and grants and verify each mutation occurs through HTTPS
- [ ] 1.2 Implement controlled password and token input and verify ordinary arguments, output, and logs contain no secret values
- [ ] 1.3 Implement `--remove-orphan-key` only for initial setup, send the
  provider's key-only recovery request, and verify the CLI has no generic force
  or database-reset behaviour

## 2. End-to-end validation

- [ ] 2.1 Run the CLI against the disposable provider and verify it has no database driver, path, or direct persistence access
- [ ] 2.2 Verify invalid trust, authentication, authorisation, and controlled-input failures are secret-safe and leave provider state unchanged
