# D'Vielle — Secure Development and Software Supply Chain Plan

Version 1.0 • 10 October 2026 • Proposed engineering process

## Development baseline

Preserve existing repair/UI changes. Before implementation, identify exact source revision, uncommitted work, dependency inputs and deployment differences. Reconcile audit findings with current source; historical reports are not current runtime truth.

Use a single reviewed policy authority. Implement small operation-centered increments that include schema, authorization, executor, verifier, recovery, UI state and tests together.

## Requirements and review

Every security-impacting change links a requirement, threat, decision and acceptance case. Review privilege, ownership, scope, data flow and compatibility before adding a tool. Code review checks failure behavior, not only the happy path.

[NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) is the verified final baseline consulted. [SSDF 1.2](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd) remains identified as an initial public draft on the inspected page. Track changes without claiming draft compliance or certification.

## Dependencies and build inputs

Inventory direct/transitive Python packages, runtime, native libraries, optional model weights, assessment tools, artwork and installer/compiler inputs. Record exact version, source, hash, license and purpose in the release SBOM. The inspected project currently has dependency ranges; a reproducible release needs resolved/pinned trusted inputs and a documented regeneration process.

Build only from reviewed source and verified dependencies in a controlled environment. Avoid executing user-writable interpreters during elevation. Verify protected staging authenticity before assigning trusted ownership. Changing permissions on an arbitrary checkout does not establish its contents are genuine.

## Integrity and provenance

Produce a release manifest tying artifact hashes to source revision, build inputs and builder identity. [SLSA provenance](https://slsa.dev/spec/v1.2/provenance) describes source/build traceability. A signed provenance record from an untrusted builder is not sufficient to trust the artifact; verify expected identities and materials.

[OpenSSF Scorecard](https://openssf.org/scorecard/) can provide repository hygiene signals. A score is supplemental evidence, not proof the application is secure.

## Secrets and signing

Keep update root keys separate from online metadata/publishing keys. Restrict access and define rotation/revocation drills. No signing key, API token or private assessment credential is committed to source, included in prompts or written to ordinary logs.

Do not assume public CI can safely receive production root keys. Use an approved signing boundary and verifiable release workflow. Signing cost/availability must be resolved without substituting unsigned elevation.

## CI and defect handling

After implementation authorization, run schema/unit checks for touched behavior, static analysis and relevant integration suites. Publish actual commands/results and skipped checks. Failed tests remain visible until resolved or the feature is removed from scope. Security findings receive severity, affected versions, owner responsibility and a verification case.

A fix closes only when the root cause and its concrete acceptance case are addressed. Add meaningful regression tests for security invariants; avoid tests that merely repeat implementation text.

## Release readiness

Deliver SBOM, license notices, manifest, build provenance, release notes, known issues, support matrix and recovery instructions together. Reverify dependency vulnerability applicability at release time using approved free sources. Version matches alone do not establish reachable exploitability.

This plan does not claim CI controls, branch protections, signed releases or reproducible builds are already deployed.
