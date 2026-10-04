# Tasks

## 1. Secure control plane

- [ ] 1.1 Add local HTTPS service startup using the active local-CA certificate and verify cleartext management access is unavailable
- [ ] 1.2 Implement atomic first-admin bootstrap and authenticated account, password, and grant mutations and verify authorisation failures do not mutate storage

## 2. End-to-end validation

- [ ] 2.1 Exercise every management operation through trusted HTTPS and verify no client database path or credential is accepted
- [ ] 2.2 Run TLS, bootstrap-race, unauthorised, and secret-safe diagnostics integration tests
