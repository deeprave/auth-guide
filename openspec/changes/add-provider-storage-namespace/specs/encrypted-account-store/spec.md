# Spec Delta

## MODIFIED Requirements

### Requirement: Explicit database lifecycle
The store SHALL use `{namespace}.sqlite3` under the selected provider storage
root and obtain its named key through the selected provider namespace. It SHALL
create a database only through explicit initialisation, reject an existing
database or key, and never create a replacement key at ordinary startup.
Migrations SHALL be an explicit administrative operation. Missing or pending
migrations SHALL be a fatal non-mutating readiness result with a plan available
to the administration CLI.

#### Scenario: A migration is pending
- **WHEN** readiness checks a database with unapplied migrations
- **THEN** it reports the pending state without modifying the database

#### Scenario: A separate storage root is initialised
- **WHEN** an operator initialises a provider with a storage root distinct from
  an existing provider
- **THEN** the store creates or examines only the distinct database and named key
