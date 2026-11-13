# Design

## Context

See [proposal.md](proposal.md) and the accompanying specification deltas. The
current CLI selects only a configuration file and derives all filesystem state
from that file's parent, while provider bootstrap, certificate, and server
runtime paths use a fixed `auth-guide` platform-secret namespace. A detached
server child currently receives only the configuration-file selection.

## Goals / Non-Goals

**Goals:**

- Resolve one effective namespace and one effective provider storage root at
  the CLI boundary before any persistent provider resource is opened.
- Retain the existing `auth-guide` platform-secret namespace by default.
- Pass the resolved values through bootstrap, CA operations, foreground and
  detached server operation, including reloads.
- Make a separate auto-guide invocation able to select isolated filesystem and
  platform-secret state deliberately.

**Non-Goals:**

- Automatically migrating an existing provider's persistent filenames.
- Changing listener/address selection, port allocation, or system-trust
  installation semantics.
- Treating a namespace as a filesystem path; filesystem isolation is controlled
  by the storage root.

## Decisions

### Resolve provider identity and storage root independently

Add global `--namespace` and `--configdir` options. Resolve namespace from the
CLI option, `AG_NAMESPACE`, then `auth-guide`. Resolve the storage root from
`--configdir`, `AG_CONFIGDIR`, the parent of an explicit `--config` or
`AG_CONFIG` file, then the existing platform default. Resolve the configuration
file from an explicit `--config`/`AG_CONFIG` value, or from
`{storage-root}/{namespace}-config.toml` when none is selected.

This preserves the user's explicit configuration file even when the storage
root is separately overridden. It also avoids overloading the namespace as a
path, which would couple platform credential-store rules to filesystem-path
rules. The alternative—making `--configdir` merely an alias for `--config`'s
parent—cannot support an explicitly located configuration file with isolated
runtime state.

### Name filesystem state by namespace

Use `{namespace}.lifecycle.lock`, `{namespace}.sqlite3`, `{namespace}.pid`,
`{namespace}.meta.json`, `{namespace}-certificates.json`, and
`{namespace}-config.toml` within the storage root. The hyphenated names apply
to public configuration and certificate metadata; the dotted names retain the
resource suffix convention used for database and lifecycle state.

The provider will not discover legacy unprefixed filenames. This makes the
change deliberately breaking and prevents ambiguous implicit migration. The
alternative legacy fallback would make a new namespaced invocation silently
adopt live state and defeat isolation.

### Represent the resolved selections as one immutable CLI value

Extend the resolved CLI configuration with the configuration file, storage
root, and namespace, and resolve it once before logging, help-sensitive command
handling, or provider initialisation. Validate that the selected namespace is
not blank before creating a platform-secret provider; validate paths through
the existing path handling rather than creating directories during resolution.

A separate global mutable configuration is rejected because the detached child,
server reload, and direct command helpers could observe different values.

### Pass explicit values through provider construction boundaries

Update bootstrap, CA command helpers, and server settings to accept the
resolved namespace and storage root explicitly. Construct the platform-secret
provider with the namespace, and construct account store, certificate authority,
and lifecycle paths with the storage root. Server settings retain both values
through reload so a changed TOML document cannot move a running provider to a
different state namespace.

Passing these values directly keeps reusable async components free of CLI or
environment lookups. An alternative of consulting environment variables inside
each component would create inconsistent precedence and make library callers
harder to isolate.

### Preserve effective selections for detached servers

When `server start` re-executes a detached child, include the effective
namespace and storage-root selections in the child arguments, alongside the
already forwarded configuration file and logging overrides. `server stop`,
`status`, and `restart` resolve the same storage root before locating lifecycle
files.

Forwarding only `--config` is insufficient when an explicit configuration file
and independent storage root are selected. Relying only on inherited
environment variables would lose command-line precedence and make process
behaviour less inspectable.

## Risks / Trade-offs

- [A user selects only a distinct namespace] → Filesystem state can still
  overlap, so documentation and tests demonstrate that an isolated instance
  selects both namespace and storage root.
- [A user selects only a distinct storage root] → Platform credential entries
  can still overlap, so the same guidance covers both selections.
- [A detached child drops an effective value] → Argument-forwarding tests cover
  namespace and storage-root propagation.
- [A distinct CA is installed into system trust] → System-trust installation
  remains an explicit, separate operator action and is not part of auto-guide
  isolation.
- [An existing provider retains legacy filenames] → Startup does not discover
  them; release notes require the operator to rename each file manually.

## Migration Plan

1. Add the resolution model, CLI/environment inputs, and namespace-specific
   filenames.
2. Thread the resolved values through bootstrap, CA, account-store, and server
   lifecycle construction.
3. Add unit and integration coverage for precedence, default compatibility,
   detached-server propagation, and state isolation.
4. Document the breaking manual migration in the changelog. Operators rename
   `auth-guide.lifecycle.lock`, `auth-guide.sqlite3`, `auth-guide.pid`,
   `auth-guide.meta.json`, `certificates.json`, and `config.toml` to the new
   default-namespace filenames before upgrading. Rollback restores the prior
   executable; no automatic state cleanup occurs.
