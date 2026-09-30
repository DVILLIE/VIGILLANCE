# DVielle TUF POUF — dvielle-json-ed25519-1

**Spec:** The Update Framework 1.0.36 (5 August 2026), https://theupdateframework.github.io/specification/v1.0.36/  
**Status:** Verification only. Privileged auto-update is off. No network fetch.

## Wire format

- Metadata is JSON. Signatures cover the canonical JSON of the `signed` object: UTF-8, no insignificant whitespace, object keys sorted by Unicode code point, control characters as `\u00xx`.
- Keys and signatures are ed25519. The key id is the sha256 hex of the canonical key object. A signature is 64 raw bytes, hex encoded.
- `spec_version` is a `1.x.y` string. Top-level roles are root, timestamp, snapshot, and targets.
- sha256 and length are required for `snapshot.json`, `targets.json`, and the one package file. A missing hash is rejected.
- `consistent_snapshot` true uses `VERSION.snapshot.json`, `VERSION.targets.json`, and `HASH.filename` for the package. Timestamp stays `timestamp.json`. Root updates are `VERSION.root.json`.
- Delegated targets roles are rejected. This client does not claim to have walked a delegation graph.

## Client rules that match the spec

- Root version N+1 must be signed by a threshold of the trusted root keys and a threshold of the new root keys. Any other root version is a rollback.
- A timestamp version lower than the trusted timestamp is a rollback. The same version aborts the cycle without replacing the installed file.
- A snapshot or targets version that moves backward, or a file that disappears from snapshot metadata, is a rollback.
- Expiration must be later than the fixed update start time. Otherwise the cycle is a freeze.
- The snapshot bytes must match the timestamp hash and length. The targets bytes must match the snapshot hash and length. The package bytes must match the targets hash and length. A mismatch is a bad hash. The previous package file is kept.

## What this POUF does not do

- It does not download from GitHub Releases or any other URL.
- It does not replace a running service, scheduled task, or helper.
- It does not measure the running process. `live_binary_attestation` stays `UNCHECKED`.
- It does not download or bundle threat feeds. Local CISA KEV and OSV loaders shipped in 2.2.0 and live outside this wire format. abuse.ch dumps are not bundled.
