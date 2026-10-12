# Provider Authorisation Specification

## Purpose

Apply current account grants and presented token scopes to every protected
provider operation.

## Requirements

### Requirement: Grant-based management authorisation
The provider SHALL require both an active account grant and presented token
scope for protected routes. `accounts:manage` authorises account creation,
deletion, grant-set mutation, password reset, and reactivation.
`accounts:read` authorises all-account reads; `tokens:manage` authorises other
accounts' token management. An active account may manage its own profile,
password, closure, and tokens. Unknown and duplicate grants SHALL fail closed.

#### Scenario: A privileged mutation is unauthorised
- **WHEN** a caller lacks the required grant or token scope
- **THEN** the provider rejects the request without mutation

#### Scenario: A grant is removed
- **WHEN** a required grant is removed from an account
- **THEN** its existing tokens cannot use that capability until the account
  later receives it again

### Requirement: Atomic grant-set mutation
The provider SHALL store account grants and token scopes as validated JSON
arrays. Account managers MAY replace a complete grant set or atomically add
and remove one or more grants from the current set. A complete replacement
SHALL NOT be combined with add/remove deltas in one request. The provider SHALL
validate and persist the resulting grant set once while holding the account
record for the mutation.

#### Scenario: A grant set is replaced
- **WHEN** an authorised account manager updates grants
- **THEN** the provider persists the complete validated replacement set

#### Scenario: Grant deltas are supplied
- **WHEN** an authorised account manager supplies grant additions, removals, or
  both
- **THEN** the provider applies the complete delta to the current grant set as
  one atomic mutation
