# D'Vielle — Threat Model and Security Control Design

Version 1.0 • 10 October 2026 • Proposed threat analysis

## Protected assets and adversaries

Protect user work and credentials, private observations, authorization policy, privileged execution, update roots, recovery state and assessment scope. Consider malicious web/download content, compromised dependencies/mirrors, local unprivileged attackers including same-user malware, stolen sessions, malicious plugins and poisoned model inputs. Administrator/kernel/firmware compromise is a distinct trust condition requiring independent recovery evidence.

Attackers may combine weaknesses. Threat coverage therefore follows entry points and privilege/data paths, rather than a list of malware names.

## Threat/control matrix

| ID | Threat and consequence | Required controls and proof |
|---|---|---|
| TH-01 | Same-user client abuses helper to alter host policy | Protected authorization, narrow operation schema; real unauthorized-caller rejection |
| TH-02 | Writable interpreter/module becomes elevated code | Trusted protected staging and dependency inventory; replacement/reparse rejection |
| TH-03 | Old/substituted update installs hostile code | Signature/version/expiry/hash verification; compromise and rollback tests |
| TH-04 | Malicious text persuades AI to grant itself authority | Model isolated from executor; injected content cannot change scope or policy |
| TH-05 | PID/path reuse causes containment of wrong program | Creation/file identity and revalidation; timed replacement tests |
| TH-06 | Crash loses outcome and duplicate action damages policy | Durable intent, serialization and actual-state reconciliation |
| TH-07 | Recovery overwrites administrator changes | Ownership markers and conditional restore; competing-change tests |
| TH-08 | VPN/QUIC/existing sessions bypass stated restriction | Route/transport/session matrix and independent traffic observation |
| TH-09 | Assessment follows redirect or DNS change outside scope | Per-action allowlist resolution and redirect enforcement |
| TH-10 | Sensitive telemetry leaks through export/log/model | Data minimization, redaction, isolated model and egress review |
| TH-11 | Stale/poisoned feed triggers harmful response | Freshness/provenance/applicability checks; no single-feed authority |
| TH-12 | Resource exhaustion makes protection ineffective | Bounded queues/workers, priority recovery and visible event loss |
| TH-13 | Kernel/firmware compromise falsifies local state | Report trust uncertainty; independent/vendor recovery paths |
| TH-14 | Compromised signing/model supply chain poisons releases | Separate roles, reviewed provenance and key/model rotation tests |

## Abuse scenarios and challenge

A hostile caller sends a valid restrict_network payload. Schema validation passes, but the requested action is unauthorized: the service must reject it. This is why correct JSON is not correct authority.

A model correctly identifies risk but asks for broad machine isolation. The policy engine can authorize only a narrow previously accepted operation. Correct analysis does not eliminate disruption or authority checks.

A firewall API reports success while a connection continues through another route. The operation remains applied but unverified/failed under its claimed scope. Configuration existence is weaker than effective behavior.

A user clicks Restore after an administrator changes protection. Recovery must preserve that change. “Return exactly to yesterday” is not a valid rule when another authority has acted.

## Prioritization

Prioritize trust-boundary violations, irreversible effects, recovery corruption and exploitable privilege paths before expanding detectors. Rank risk using credible likelihood, impact and evidence uncertainty; do not invent numeric probabilities. Treat externally reported exploitation and reachable vulnerable components as context, not proof of host compromise.

## Control verification

Each mitigation has a negative test and an independent observable postcondition. Test benign workflows as carefully as harmful cases. Source review identifies a defect or design claim; real Windows integration establishes behavior for declared builds. Full endpoint certification is not inferred from ASVS web/API coverage or passing unit tests.

The process follows decomposition, threats, mitigations and validation in [OWASP threat modeling guidance](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html). Review the model after every authority, data-flow or deployment change.
