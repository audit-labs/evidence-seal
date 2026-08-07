# evidence-seal

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()

Tamper-evident seals and chain of custody for audit evidence packages.

Every Audit Labs tool assumes the evidence it handles is authentic. `evidence-seal`
is what makes that assumption checkable. Point it at a directory of evidence — an
[audit-tools](https://github.com/audit-labs/audit-tools) package, a folder of
exported screenshots, anything — and it writes a `manifest.json` that pins every
file's SHA-256 into a single Merkle fingerprint. Later, `verify` proves the
directory is byte-for-byte what was sealed, and names anything that changed.

- **Integrity** — detect any modified, added, or removed file.
- **Chain of custody** — link sequential seals so a series of dated packages
  forms an append-only history; reordering or removing one is detectable.
- **Attribution** *(optional)* — sign a manifest with an ed25519 key so a named
  party attests "I collected this," not just "it is unchanged."
- **Trusted time** *(optional)* — obtain an RFC 3161 timestamp from an
  independent authority so the seal is provably *not backdated*.

The core (`seal`, `verify`, `chain`) is **pure standard library** — no
dependencies. Signing needs `cryptography` (`evidence-seal[sign]`) and
timestamping needs `asn1crypto` (`evidence-seal[timestamp]`).

## Install

```bash
# Core is pure standard library; extras add signing + timestamping.
pip install "evidence-seal[sign,timestamp]"

# Or, for the zero-dependency core, drop the extras:
pip install evidence-seal
```

To hack on it from a clone instead, see [Development](#development).

## Usage

```bash
# Seal a package (manifest written to <dir>.manifest.json alongside it)
evidence-seal seal ./output/aws_audit_prod_2026-01-01 \
  --meta engagement=ACME-2026 --meta collector="Christian Cleberg"

# Later, prove nothing changed
evidence-seal verify ./output/aws_audit_prod_2026-01-01
# -> intact — 8 files match the seal        (exit 0)
# -> TAMPERED …  MODIFIED iam_users.csv      (exit 1)
```

### Chain of custody

Seal each new package against the previous manifest to build a verifiable
timeline:

```bash
evidence-seal seal ./pkg_jan --out seals/jan.json
evidence-seal seal ./pkg_feb --out seals/feb.json --prev seals/jan.json
evidence-seal seal ./pkg_mar --out seals/mar.json --prev seals/feb.json

evidence-seal chain seals/jan.json seals/feb.json seals/mar.json
# -> chain intact — 3 seals link correctly
```

Each manifest's `id` is the hash of its own canonical contents, and `previous`
holds the prior manifest's id — so a broken, reordered, or spliced-out link is
caught.

### Signing (attribution)

```bash
evidence-seal keygen --private acme.key --public acme.pub   # once
evidence-seal seal ./pkg --sign acme.key                    # seal + sign
evidence-seal verify ./pkg --pubkey acme.pub                # require this signer
```

Without `--pubkey`, a present signature is still checked for validity; with it,
the signer's key must also match, proving *identity* and not just integrity.

### Timestamping (trusted time)

A signature says *who*; a timestamp says *when*, attested by an independent
Time-Stamp Authority rather than the sealer's own clock. The TSA timestamps the
manifest `id`, so one token vouches for the whole package.

```bash
# One step: request, POST to a TSA, and bind the token in
evidence-seal timestamp submit pkg.manifest.json --tsa https://freetsa.org/tsr

# Or split it — build a request, submit it however you like, then apply
evidence-seal timestamp request pkg.manifest.json --out pkg.tsq
curl -sS -H 'Content-Type: application/timestamp-query' \
  --data-binary @pkg.tsq https://freetsa.org/tsr -o pkg.tsr
evidence-seal timestamp apply pkg.manifest.json --token pkg.tsr

evidence-seal timestamp verify pkg.manifest.json
# -> timestamp OK: timestamped at 2026-08-06T09:00:00Z

# Full verification: also check the token's CMS signature against the TSA cert
evidence-seal timestamp verify pkg.manifest.json --tsa-cert freetsa.pem
# -> timestamp OK: timestamped at 2026-08-06T09:00:00Z; TSA signature valid (CN=…)
evidence-seal verify ./pkg --tsa-cert freetsa.pem   # same check inside a full verify
```

`apply` refuses any token whose imprint is not this manifest's `id`. Because the
`id` moves if a single byte changes, a token can never be transplanted onto
tampered evidence — re-sealing after a change orphans the timestamp. A present
timestamp is checked automatically during `verify`.

With `--tsa-cert`, the token's RFC 3161 CMS signature is verified against the
supplied certificate: the certificate must carry the timeStamping extended key
usage, identify the token's signer, be valid at `gen_time`, and its key must
verify the signature over the timestamped content. This authenticates the token
against a TSA certificate you trust; establishing that the certificate itself
chains to a known root is left to you (supply a cert you already trust).

## The manifest

Canonical JSON, sorted keys — diff-friendly and reproducible:

```json
{
  "algorithm": "sha256",
  "created_at": "2026-08-06T08:06:05Z",
  "subject": "aws_audit_prod_2026-01-01",
  "previous": null,
  "metadata": { "collector": "Christian Cleberg", "engagement": "ACME-2026" },
  "root": "23fdf7eb…",
  "file_count": 8,
  "files": [ { "path": "iam_users.csv", "sha256": "309b0e45…", "bytes": 412 } ],
  "id": "08b846a0…",
  "signature": { "algorithm": "ed25519", "public_key": "1bea5f1d…", "value": "2d7c2d63…" },
  "timestamp": { "format": "rfc3161", "gen_time": "2026-08-06T09:00:00Z", "imprint": "08b846a0…", "token": "MIIB…" }
}
```

- **`root`** — Merkle root over all `(path, sha256)` leaves; one value that
  changes if any file, name, or byte changes.
- **`id`** — SHA-256 of the manifest's canonical form (excluding `id`,
  `signature`, and `timestamp`); makes it self-verifying and chainable. Because
  the signature and the timestamp both attest *to* the id, they sit outside it
  and compose in any order.
- **`ignore`** — glob patterns skipped at seal time; `verify` reuses them so it
  never false-flags an intentionally excluded file.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Intact / valid. |
| `1` | Tamper detected, chain broken, or signature invalid. |
| `2` | Usage error (missing directory, bad `--meta`, missing optional dependency). |

Fail a pipeline on `1`; treat `2` as a misconfiguration to fix.

## Threat model

`evidence-seal` proves a directory matches a manifest, who produced it (when
signed), and that it existed by a given time (when timestamped). An *unsigned,
untimestamped* manifest can be regenerated by anyone with the files, and its
`created_at` is self-reported. For a strong "sealed at time T by party P"
guarantee, **sign** the manifest (retain the public key out of band) and
**timestamp** it with a trusted TSA.

**What a seal does not prove.** A seal proves the *package* is unchanged since it
was sealed — nothing more. It says nothing about whether the collection faithfully
represented the system at collection time: whether the right scope was captured,
whether a query was complete, or whether the evidence was gathered from the
production system at all. That is the question an auditor actually asks, and it is
answered by collection controls and re-performance, not by this tool. Seal the
evidence; don't mistake an intact seal for a trustworthy collection.

Further limits to be honest about:

- **`timestamp verify` checks the binding; `--tsa-cert` adds signature
  verification but not chain-of-trust.** Without a cert, verification proves the
  stored token timestamps this manifest's `id`. With `--tsa-cert`, it also
  verifies the token's CMS signature, the timeStamping EKU, the signer match,
  and validity at `gen_time`. It does **not** verify that the certificate chains
  to a trusted root — supply a TSA certificate you already trust.
- Private keys are written **unencrypted** — store them accordingly.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
./scripts/e2e.sh   # every feature end-to-end through the CLI, offline
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
