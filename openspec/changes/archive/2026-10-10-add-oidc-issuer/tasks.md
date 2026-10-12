# Tasks

## 1. Issuer service

- [ ] 1.1 Implement trusted-HTTPS discovery, JWKS, readiness, and signing-key lifecycle and verify clients discover active and overlap keys
- [ ] 1.2 Implement browser authentication and short-lived user/admin bearer issuance and verify invalid credentials never produce a bearer

## 2. Lifecycle validation

- [ ] 2.1 Add account-removal, token-expiry, insufficient-scope, and key-rotation end-to-end issuer tests
- [ ] 2.2 Document and test readiness and managed-process invocation without implementing the separate Guide adapter
