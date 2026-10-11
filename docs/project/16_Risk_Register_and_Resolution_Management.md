# D'Vielle — Risk Register and Resolution Management

Version 1.0 • 10 October 2026 • Initial design risk baseline

## Interpretation

Risk ratings below express engineering priority, not measured incident probability. “Open” means a design or proof obligation remains. A proposed solution is not treated as a implemented mitigation. Every release decision names which risks are reduced, excluded, accepted or still unresolved.

## Register

| ID | Risk / priority | Proposed resolution | Closure evidence |
|---|---|---|---|
| RK-01 | Privileged caller abuse / Critical | Protected policy, narrow service, OS identity plus independent authorization | VT-02 and protected installation review |
| RK-02 | Writable elevated input / Critical | Authentic protected staging/runtime and verified dependencies | VT-08 replacement/reparse cases |
| RK-03 | Lost/duplicate mutation / Critical | Durable intent, resource claims, reconciliation | VT-04 crash matrix |
| RK-04 | Recovery destroys external edits / Critical | Owned changes, compare actual state before restore | VT-05 conflict cases |
| RK-05 | Claimed containment ineffective / High | Exact adapter semantics and independent network tests | VT-06 supported-route evidence |
| RK-06 | AI grants or leaks authority / High | Restricted worker, structured proposal, deterministic gate | VT-11 hostile-content cases |
| RK-07 | Telemetry/privacy leakage / High | Minimal schema, isolated data flow, redacted export | VT-10 actual egress/storage review |
| RK-08 | Update/signing compromise / Critical | TUF roles, provenance, rotation, trusted activation | VT-08 compromise/rotation drills |
| RK-09 | Scope escapes target / High | Per-action checks including DNS/redirects and stop | VT-09 authorized integration |
| RK-10 | Resource overload hides gaps / High | Bounded queues/process accounting, visible loss | VT-07/VT-13 overload workloads |
| RK-11 | PQ capability overstated / High | Capability and actual negotiation/auth separated | VT-12 peer/provider records |
| RK-12 | Unsupported OS behavior / High | Capability matrix, build-specific validation, truthful degradation | Platform acceptance results |
| RK-13 | Flash/inaccessible UX / High | Reduced motion and native accessibility verification | VT-14 and flash analysis |
| RK-14 | Free tool licensing mismatch / High | Exact artifact/license review; no forbidden bundling | Release notices and dependency ledger |
| RK-15 | Unfunded maintenance/support / High | Local-first service design and measured sustainability | Owner-approved operating model |
| RK-16 | Local state falsified by deep compromise / High | Independent recovery/attestation options, trust-state reporting | Vendor/platform-specific recovery evidence |
| RK-17 | Misleading superiority claim / High | Declared comparative benchmark with real results | Independent comparative report |
| RK-18 | Global obligations misunderstood / High | Actual entity/market/data-flow applicability analysis | Distribution/legal review before publication |

All entries begin Open for this proposed advancement baseline. Existing source repairs may address parts; their evidence must be mapped and refreshed rather than credited wholesale.

## Resolution workflow

For each risk, establish root cause and affected scope, choose the smallest effective control, challenge it with a counterexample, define the required observable outcome and implement/test it only after authorization. Link source revision, test record and residual scope. Reopen on new evidence or platform change.

A fallback should preserve useful protection. Examples: observe-only when helper authority is unproven; quarantine candidate learned rules; disable an unsupported assessment adapter; present independent recovery when local trust is doubtful.

## Escalation and acceptance

Unauthorized mutation, unsafe installation, unresolved recovery or false verification block the related capability. Product convenience does not waive these conditions. Risk acceptance requires an explicit human decision with scope and rationale; silence or a polished document is not acceptance.

## Devil's advocate questions

Can an authorized-looking hostile client issue the action? Can a different program inherit the target identity? Can an administrator's later change be overwritten? Can the output say verified while the actual connection continues? Can a dependency/model update change authority? Can a benchmark exclude adverse workloads?

Each question has corresponding tests. The separate resolution dossier develops these mechanisms rather than leaving the register as a checklist.
