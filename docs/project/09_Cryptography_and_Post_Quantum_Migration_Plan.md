# D'Vielle — Cryptography and Post-Quantum Migration Plan

Version 1.0 • 10 October 2026 • Proposed migration specification

## Security properties

Treat confidentiality, integrity, authentication, key establishment and update authorization separately. A successful hybrid key exchange does not establish post-quantum server authentication. A library supporting an algorithm does not establish its use in the application.

Post-quantum cryptography runs on conventional computers. Quantum key distribution requires different physical infrastructure; it is not a software update to this guardian.

## Inventory before migration

Record each cryptographic asset: owning component, purpose, algorithm/parameters, provider/version, key/certificate type, creation/expiry, storage/rotation, protocol, peer dependencies, actual negotiated state and business/data lifetime. Distinguish inferred usage from measured usage. Represent compatible inventory using [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/).

Prioritize long-lived sensitive data, externally exposed protocols, update trust and identity material. Determine whether the application controls each protocol. Vendor software cannot be made PQ-safe simply by changing a guardian setting.

## Algorithm and protocol strategy

Use standardized [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) for supported key-establishment protocols and [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)/SLH-DSA where authentication ecosystems support them. Use maintained authenticated encryption for data after key establishment. Follow [NIST KEM integration guidance](https://csrc.nist.gov/pubs/sp/800/227/final), current errata and provider documentation.

Choose supported hybrid exchanges where interoperability and the protocol design call for them. Do not invent a combiner, certificate extension or ad hoc cryptographic protocol. Record negotiation and authentication separately in the UI and report.

Windows CNG and third-party provider capability must be probed on exact builds. Previous research identified production availability announcements and older documentation wording; runtime detection plus real interoperability resolves that discrepancy. No universal platform availability is assumed.

## Key lifecycle

Generate keys through vetted providers and appropriate randomness. Restrict access, avoid ordinary logs/prompts, define rotation/revocation and test backup/recovery. Keep update root authority separate from online publishing keys. Protect offline roots and document lost-key recovery before release.

A new signature family does not replace Windows package-signing compatibility automatically. Maintain platform-compatible distribution while evaluating application-layer PQ metadata with explicit verifier support and migration semantics.

## Migration stages

1. Inventory current dependencies/protocols and identify data lifetime.
2. Probe providers and supported peers; record capability.
3. Implement a reviewed protocol adapter in a controlled environment.
4. Validate actual exchange, authentication, downgrade handling and malformed input.
5. Test rotation, recovery and mixed-version compatibility.
6. Roll out through signed versioned configuration with rollback and visible coverage.
7. Track standards corrections and rerun affected integration cases.

## Downgrade and offline behavior

For a connection requiring a declared cryptographic property, refuse silent fallback below that policy and explain the incompatibility. Where compatibility fallback is accepted, record it explicitly. Offline operation retains local observation and recovery; expiry of update metadata must not be silently waived to make the UI green.

## Acceptance

Produce real provider/build inventories and handshake records for supported peers. Test invalid keys/ciphertexts/signatures, failed entropy/provider initialization, rotation and peer mismatch. Measure resource overhead and latency. A configuration value, imported library or quantum-looking logo is not acceptance evidence.

No post-quantum protection has been implemented or measured by this document.
