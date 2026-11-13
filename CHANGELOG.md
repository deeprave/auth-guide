# Changelog

## v0.6.0 - 2026-11-13

### Breaking changes

- Provider state filenames are now namespace-specific. Before upgrading, manually
  rename `auth-guide.lifecycle.lock`, `auth-guide.sqlite3`, `auth-guide.pid`,
  `auth-guide.meta.json`, `certificates.json`, and `config.toml` to
  `{namespace}.lifecycle.lock`, `{namespace}.sqlite3`, `{namespace}.pid`,
  `{namespace}.meta.json`, `{namespace}-certificates.json`, and
  `{namespace}-config.toml`, respectively. Legacy filenames are not read.
