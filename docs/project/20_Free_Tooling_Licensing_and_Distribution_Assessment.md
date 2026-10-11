# D'Vielle — Free Tooling, Licensing and Distribution Assessment

Version 1.0 • 10 October 2026 • Proposed dependency and distribution policy

## Selection policy

Prefer built-in Windows capabilities, project-owned logic and free publicly documented sources. Evaluate availability, rights, redistribution, data disclosure, maintenance and actual efficacy separately. No paid service is a required core dependency. “Free to use” never automatically means “free to bundle” or “unlimited hosted use”.

## Candidate ledger

| Candidate | Verified licensing/access observation | Proposed use |
|---|---|---|
| NIST ACTS | Project states public domain/free; download link by request | Development interaction coverage; request not sent |
| TLA+/TLC | Public tool/source access; review exact release license | Development state-model verification |
| OSV | Public version/commit-query API; current docs state no rate limit | Optional inventory enrichment with bounded cache/backoff |
| FIRST EPSS | Free daily CSV/API without registration; API for lookup | CVE prioritization context; CSV for bulk |
| ZAP | Core Apache-2.0; package has mixed third-party licenses | Optional scoped web assessment; review full shipped package |
| osquery | Repository declares Apache-2.0 OR GPL-2.0-only | Optional inventory under reviewed artifact/license choice |
| Atomic Red Team | Repository MIT | Selected authorized development tests; not automatic default execution |
| Sysinternals | Free use; Microsoft FAQ says no redistribution licenses | User-provided/officially obtained tool only if needed |
| URLhaus | Community API requires Auth-Key and fair-use review | Optional connector only after actual usage fits terms |
| Google Safe Browsing | Free but non-commercial usage restrictions and quotas | Conditional optional use; no assumed universal distribution right |
| Local AI weights | Rights vary by exact model/version | Admit only reviewed free compatible artifact |
| Windows controls | Availability/management vary by edition/build | Capability probe and local adapter; no enterprise service dependency |

## Free architecture resolution

A feed that does not fit project terms is excluded rather than replaced by an unsolicited paid service. Core protection uses measured local evidence, accepted Windows controls, verified updates and recovery. Optional feeds add context but are not required to claim an action verified.

For URL reputation, retain built-in browser protection and optional permitted feeds. A feed missing an unknown URL is not evidence it is safe. Do not fabricate reputation from a model. Publicly documented malware feeds are not necessarily phishing coverage.

OSV/EPSS reduce dependency-prioritization cost but do not identify every Windows proprietary-software vulnerability or prove exploitability. Build source adapters around clear applicability semantics.

## Release license process

Record every artifact's version, source URL, hash, license, notices, modifications and redistribution obligations. Include native/transitive dependencies and bundled models. ZAP's permissive core does not erase obligations of bundled libraries. osquery's dual-license choice must be deliberate and recorded for the exact artifact.

The inspected project metadata declares MIT, but that is not a verified complete legal inventory or a trademark clearance. Existing license/copyright remains unchanged.

## Distribution and legal applicability

A worldwide release requires actual operator/entity, target markets, data flows, hosting and commercial/nonprofit model facts. Free end-user price alone does not resolve privacy/product-security obligations. Research located official GDPR and EU Cyber Resilience Act texts. Canonical pages returned anti-bot interstitials; the official CRA PDF was subsequently retrieved. GDPR retrieval remained unavailable. No complete legal applicability analysis is claimed.

Before publication, review applicability using accessible official texts and qualified interpretation where needed. Prepare public privacy/terms/VDP wording from verified runtime behavior and operating commitments. Do not fabricate an approved policy, support promise or legal exemption in a document.

## Cost and continuity

Budget release hosting, signing, review, recovery testing and support honestly. Local-first operation and cacheable signed downloads reduce variable service dependence. No specific sponsor, certificate or grant is claimed available. If a cloud service is unaffordable, keep the core offline-capable rather than selling private telemetry.

Sources: [ZAP notice](https://github.com/zaproxy/zaproxy/blob/main/LEGALNOTICE.md), [osquery license](https://github.com/osquery/osquery/blob/master/LICENSE), [Atomic Red Team license](https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt), [Sysinternals FAQ](https://learn.microsoft.com/en-us/sysinternals/license-faq), [URLhaus API](https://urlhaus.abuse.ch/api/), [abuse.ch terms](https://abuse.ch/terms-of-use/), [Safe Browsing usage](https://developers.google.com/safe-browsing/reference/Appropriate.Usage).
