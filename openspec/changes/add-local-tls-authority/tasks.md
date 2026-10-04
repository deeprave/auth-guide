# Tasks

## 1. Authority and trust

- [ ] 1.1 Create CA and leaf-key secret references with public certificate metadata and verify private keys are absent from storage and configuration
- [ ] 1.2 Add explicit macOS and Linux root-trust install/uninstall flows and verify a system TLS client trusts the issued leaf

## 2. Lifecycle

- [ ] 2.1 Implement leaf issue, activation, rotation, retirement, and metadata audit and verify new HTTPS connections use the active leaf
- [ ] 2.2 Implement emergency CA rotation and verify old-root removal prevents trust while the replacement chain succeeds
