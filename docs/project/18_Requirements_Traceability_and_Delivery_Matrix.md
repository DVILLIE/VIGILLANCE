# D'Vielle — Requirements Traceability and Delivery Matrix

Version 1.0 • 10 October 2026 • Initial advancement traceability baseline

## Matrix semantics

PR requirements define product intent. SR requirements define software obligations. TH entries identify threats; RK entries track delivery risks; VT entries define validation classes. Step numbers refer to the detailed implementation plan.

Rows below preserve the initial planning baseline. Implementation has subsequently started; [current progress and acceptance evidence](../implementation/IMPLEMENTATION_PROGRESS_AND_ACCEPTANCE_EVIDENCE_2026-10-10.md) identifies implemented source, actual tests and outstanding work. No row is accepted merely because its source tests pass. References below identify integration boundaries rather than deployment certification.

| Requirement | Threat / risk | Candidate source boundary | Implementation step | Validation |
|---|---|---|---:|---|
| SR-01 | TH-05/TH-11, RK-05 | agent/evidence.py, collectors, store | 12 | VT-01 |
| SR-02 | TH-06, RK-03 | controller/store/GUI lifecycle | 6,10,12 | VT-01/VT-04 |
| SR-03 | TH-01, RK-01 | agent/privilege/contract.py | 9 | VT-02 |
| SR-04 | TH-01, RK-01 | privilege transport/policy | 7,8 | VT-02 |
| SR-05 | TH-05, RK-05 | broker/executor target binding | 8,9 | VT-03 |
| SR-06 | TH-06, RK-03 | journal/controller/store | 4,6 | VT-04 |
| SR-07 | TH-08, RK-05 | firewall verification/controller | 10,11 | VT-06 |
| SR-08 | TH-07, RK-04 | recovery/ownership | 6,10 | VT-05 |
| SR-09 | TH-11/TH-12, RK-10 | capability/runtime/intelligence | 12,14 | VT-07 |
| SR-10 | TH-09, RK-09 | isolated assessment adapters | 17 | VT-09 |
| SR-11 | TH-12, RK-10 | runtime/policy/worker admission | 14,15 | VT-15 |
| SR-12 | TH-14, RK-11 | crypto inventory/protocol adapter | 16 | VT-12 |
| SR-13 | TH-02/TH-03, RK-02/RK-08 | installer, agent/update/tuf.py | 5,19 | VT-08 |
| SR-14 | TH-10, RK-07 | store/export/privacy controls | 14 | VT-10 |
| SR-15 | TH-09, RK-09 | assessment worker/scope | 17 | VT-09 |
| PR-01 | RK-15 | local runtime/default configuration | 2,14,20 | VT-15 |
| PR-02 | TH-11, RK-12 | capability and finding UI | 12,18 | VT-07 |
| PR-03 | TH-06, RK-17 | explanation/work log | 10,12,18 | VT-01/VT-14 |
| PR-04 | TH-01/TH-06 | policy, executor, verifier, recovery | 4–11 | VT-02–VT-06 |
| PR-05 | TH-07, RK-04 | Windows control ownership | 9–11,19 | VT-05/VT-08 |
| PR-06 | TH-10, RK-07 | privacy/store/export | 14 | VT-10 |
| PR-07 | RK-13 | GUI/accessibility/motion | 18 | VT-14 |
| PR-08 | TH-09, RK-09 | ethical assessment boundary | 17 | VT-09 |
| PR-09 | RK-11 | crypto inventory/adapters | 16 | VT-12 |
| PR-10 | TH-04/TH-11 | evidence graph/decision engine | 13,15 | VT-01/VT-11 |

## Evidence record requirements

Each actual validation record identifies requirement/test ID, source/artifact hash, OS/build/hardware, configuration, prerequisite status, authorized assets, test procedure, observed result, logs/evidence locations, reviewer and residual scope. A screenshot alone is not proof of an underlying enforcement effect.

Report Failed, Blocked, Not evaluated and Not applicable distinctly. Not applicable requires a reason and release scope. A skipped integration case remains unverified.

## Updating and consistency

A new operation must add requirement, threat, risk, authorization/execution/recovery contract and tests. A protocol/schema change must update interface and compatibility records. A discovered bypass reopens affected requirement acceptance and claims, even if prior unit tests still pass.

Maintain source-to-deployment mapping so the shipped artifact can be associated with the evidence. Never infer that tests in one checkout certify another checkout or an installed runtime.

## Release decision use

The release owner reviews this matrix alongside actual acceptance results and known issues. Rows with unsafe authority, recovery or false verification block the related capability. Unsupported advanced features can be omitted explicitly; omission cannot be hidden behind a general “protected” banner.

This matrix is populated with planning links. The linked implementation record supplies bounded current evidence; full release acceptance remains outstanding.
