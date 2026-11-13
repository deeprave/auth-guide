# Spec Delta

## MODIFIED Requirements

### Requirement: Conventional PID-file lifecycle state
The server runtime SHALL record its PID as a decimal value in the selected
provider storage root as `{namespace}.pid` in both background and foreground
modes. It SHALL record the effective listener address in sibling
`{namespace}.meta.json` metadata.

#### Scenario: Metadata records the active listener
- **WHEN** the server runtime records its lifecycle state
- **THEN** `{namespace}.meta.json` in the selected storage root contains the
  effective `listen` address and a readiness `generation` counter

#### Scenario: Isolated provider lifecycle state is recorded
- **WHEN** a provider starts with a storage root distinct from a live provider
- **THEN** it does not read, replace, or remove the live provider's PID or
  metadata files

### Requirement: Exclusive lifecycle-state mutation
The server runtime SHALL use `{namespace}.lifecycle.lock` in the selected
provider storage root to coordinate examination, creation, replacement, and
removal of its PID and metadata pair. Before startup, while holding that lock,
it SHALL reject a live existing PID without changing metadata, and remove stale
PID and orphan metadata files before creating its own state. It SHALL
exclusively create its PID file before atomically writing generation-0 metadata.

#### Scenario: A stale PID file is encountered
- **WHEN** the server runtime starts and the selected namespace PID is no longer live
- **THEN** it removes that namespace's stale PID and metadata files before recording its own state

#### Scenario: A live provider is already running
- **WHEN** a foreground or background runtime starts while the selected namespace PID file names a live process
- **THEN** startup is rejected without changing that PID file

#### Scenario: A concurrent start is attempted
- **WHEN** another runtime for the same namespace attempts to start while lifecycle state is being created, replaced, or removed
- **THEN** the second start is rejected without creating a second runtime
