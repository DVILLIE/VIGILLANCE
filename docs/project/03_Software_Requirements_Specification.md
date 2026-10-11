# D'Vielle — Software Requirements Specification

Version 1.0 • 10 October 2026 • Normative proposed requirements

## Interpretation

“Shall” expresses a proposed acceptance obligation after baseline approval. None of these requirements is claimed passed merely because it is documented. Tests map to requirements in the traceability matrix. Supported builds and numerical performance budgets are release-specific decisions determined before corresponding evaluation.

## Functional requirements

| ID | The software shall… | Verification |
|---|---|---|
| SR-01 | Record source, target identity, observation time, ingestion time and sensor health for every actionable event | Schema validation and actual collector inspection |
| SR-02 | Distinguish evidence, inference, proposal, authorization, execution and verification records | Lifecycle integration test |
| SR-03 | Reject unsupported operations, unknown parameters and malformed privileged requests before mutation | Contract rejection tests and OS integration |
| SR-04 | Authenticate caller identity and validate operation-specific authorization independently of model content | Unauthorized caller tests |
| SR-05 | Bind authorization to exact target/scope and recheck freshness and identity before mutation | Replacement and stale-token cases |
| SR-06 | Write durable intent before mutation and reconcile interrupted outcomes before subsequent conflicting mutations | Crash-boundary tests |
| SR-07 | Verify actual postconditions independently of executor return values | Outcome disagreement test |
| SR-08 | Restore only owned changes and preserve intervening external edits | Recovery conflict cases |
| SR-09 | Display loss of sensor, feed or enforcement coverage explicitly | Sensor disconnect/stale feed cases |
| SR-10 | Enforce scope for every assessment request, redirect and resolved address | Scope escape tests |
| SR-11 | Preserve working local protection when optional inference or internet access is unavailable | Offline/model-unavailable cases |
| SR-12 | Report cryptographic capability separately from actual negotiated exchange and authentication | Real interoperability tests |
| SR-13 | Validate update signatures, metadata freshness, versions and artifact hashes before protected activation | Update rejection/recovery tests |
| SR-14 | Expose redacted export, retention controls and deletion behavior | Export review and lifecycle tests |
| SR-15 | Stop initiating assessment actions promptly on stop/scope expiry and reconcile actions already underway | Cancellation and expiry tests |

## Nonfunctional requirements

**Security.** Privileged code, interpreters, dependencies and policy are protected from unprivileged replacement. Unknown authority is denied. A same-user identity alone is insufficient evidence of genuine approval. Every operation has explicit rights and supported postconditions.

**Reliability.** Corrupt journals, unavailable storage and incomplete reads prevent unsafe new mutations. The application records dropped telemetry and distinguishes healthy from merely running. Restart must not convert an unknown effect into a clean success.

**Performance.** Measure the entire application process tree, optional models, child tools, animation and associated services. Record CPU time, peak/steady memory, disk/network use, startup time and foreground task latency against an agreed workload baseline. Admit components only against the approved budget. A CPU cap alone is not a responsiveness guarantee.

**Privacy.** Collection is purpose-limited. Content capture and export require explicit policy. Network destinations and executable paths may identify a user and receive restricted retention/access. Optional remote services are disabled until their distinct data flow is accepted.

**Accessibility.** Essential actions are keyboard reachable, status has text equivalents, scaled text remains readable and decorative animation can be stopped. Test native accessibility behavior rather than assuming a widget library provides it.

**Compatibility.** Identify edition, build, antivirus posture and management policy before selecting controls. Do not take ownership of another administrator's policy. Degradation retains useful observation and displays the unavailable action.

## Environmental and interface constraints

The inspected project metadata specifies Python >=3.12,<3.13 and a Python desktop application. This is a source fact, not a future platform decision. Preserve legacy identifiers when necessary for compatibility while user-facing branding uses D'Vielle.

The current helper contract defines restrict_network only. ASR/CFA expansion requires a separate reviewed operation contract; the GUI must not discover extra authority through arbitrary command strings. Production authentication and trusted installation are prerequisites to automatic privileged execution.

## Failure reporting

Use machine-readable errors: unsupported_operation, unauthorized, stale_identity, scope_violation, precondition_changed, storage_unavailable, enforcement_unavailable, verification_failed, outcome_unknown and recovery_conflict. Human messages explain the practical effect and next supported action without exposing secrets.

The release report lists each requirement as accepted, failed, blocked, not evaluated or not applicable with justification. Omitted evidence is not a pass.
