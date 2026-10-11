# D'Vielle — Privacy, Data Governance and Impact Assessment

Version 1.0 • 10 October 2026 • Proposed internal policy and privacy assessment

## Purpose and default posture

Process the minimum data needed to observe security state, explain decisions and recover owned changes. Local-first is a design requirement, not proof that all existing modules have zero egress. Verify actual network behavior before making that claim publicly.

This document assesses engineering privacy risks. It is not a published legal privacy notice or a declaration of worldwide legal compliance.

## Data inventory and disposition

| Data class | Purpose | Proposed handling |
|---|---|---|
| Process identity, executable path/hash | Correct target attribution | Local restricted store; redact identifying path segments in exports |
| Network endpoint/protocol/time | Network investigation and verification | Local; avoid unnecessary payload capture |
| OS/security posture | Capability and policy selection | Local; export only relevant settings |
| Vulnerable component/version | Applicability and prioritization | Local inventory; disclosed lookup queries require accepted policy |
| User documents, message contents, screenshots | Usually unnecessary | Not collected by default; separate explicit feature policy |
| Credentials/session tokens | Not needed for routine protection | Never put in ordinary logs/prompts; assessment credentials isolated |
| Operation/recovery state | Explain and restore owned effects | Restricted durable retention until resolved |
| Diagnostics/crash reports | Repair application failures | Local by default; redacted opt-in external submission |

## Retention and deletion

Propose a default rolling 30-day observation history and 90-day resolved operation history, configurable within the supported storage budget. These durations are design proposals, not verified runtime defaults. Unresolved recovery records remain until reconciled because deleting them can destroy safe restoration.

Deletion removes logical records, auxiliary exports and associated diagnostics within the declared scope. Explain that SSD/storage-level forensic erasure is not guaranteed by deleting a database row. When encryption is used, document key destruction and backup copies separately. Do not delete independent user backups silently.

## Access and export

Separate ordinary user observation from protected privileged intent. Restrict access to the installed user and authorized administrators as appropriate, while avoiding administrator writes through user-controlled paths. Apply redaction before export, provide a preview/manifest and exclude credentials by construction. Hashes of rare private files can still identify content; do not describe hashing as universal anonymization.

## Risk assessment

**Overcollection:** solve through field-level purpose mapping and payload exclusion. Verify collected/exported schemas.

**Unexpected disclosure:** solve through outbound adapter allowlists, query minimization, disabled remote inference and opt-in diagnostics. Verify with actual traffic inspection on owned machines.

**Sensitive inference:** separate “unusual connection” from intent/identity allegations. Provide factual context and correction controls.

**Shared computer exposure:** bind records and policy to installation/user context; test session boundaries and exported paths.

**Retention conflicts:** preserve unresolved recovery while minimizing historical observation. Display the reason records are retained.

## Remote services and international distribution

Before any hosted account, cloud model or automatic diagnostic upload, define operator, purposes, payload, location, recipients, retention, deletion and applicable obligations. Do not assume free distribution removes legal duties. The legal/distribution assessment records questions that require the actual operating entity and deployment facts.

Use [NIST Privacy Framework](https://www.nist.gov/privacy-framework) for risk organization. Its page currently surfaces version 1.1 initial public draft material; draft guidance must be labeled accordingly.

## Acceptance evidence

Capture real ingress/egress and stored schemas for declared workflows. Verify exports contain only selected fields, secrets are excluded, disabled sharing remains disabled and deletion honors its stated scope. Keep privacy evidence separate from security efficacy. No existing privacy behavior is certified by this proposal.
