# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `evidence_seal.sshsig`: SSH signatures (OpenSSH `PROTOCOL.sshsig`) with Ed25519 keys, interchangeable with `ssh-keygen -Y`.
- `evidence-seal signoffs <dir> --trust <fingerprint>`: offline verification of a firm-signed team roster (`team.json`, `team.json.sig`) and signed sign-off statements (`signoffs.jsonl`).
- `sign_manifest(..., password=...)` for encrypted PEM keys.

## [1.0.0] - 2026-08-07

First stable release. The `manifest.json` schema (`manifest_version`) and the CLI
exit codes are now a committed contract: neither changes in a breaking way without
a major-version bump.

## [0.1.0] - 2026-08-06

### Added

- Tamper-evident seals and chain of custody: streaming SHA-256 with a path-bound
  Merkle root over a directory, written to a canonical `manifest.json`.
- Append-only seal chains via `previous`, with the `ignore` globs stored so
  `verify` reuses them.
- Optional ed25519 signing (`[sign]` extra) and RFC 3161 timestamping
  (`[timestamp]` extra), including full TSA-signature verification with `--tsa-cert`.
- CLI subcommands `seal`, `verify`, `chain`, `keygen`, `sign`; exit codes
  0 (intact), 1 (tamper / broken / invalid signature), 2 (usage).
- PyPI trusted-publishing release workflow.

[1.0.0]: https://github.com/audit-labs/evidence-seal/releases/tag/v1.0.0
[0.1.0]: https://github.com/audit-labs/evidence-seal/releases/tag/v0.1.0
