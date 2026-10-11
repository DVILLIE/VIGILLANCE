# D'Vielle — Step-by-Step Implementation Plan

Version 1.1 • 10 October 2026 • Detailed implementation work breakdown

## Execution condition and baseline

The owner subsequently authorized implementation, including an Advanced Ethical Hacking workspace. Implementation has started in the repair checkout. Current source changes, actual checks and remaining acceptance work are recorded in [Implementation Progress and Acceptance Evidence](../implementation/IMPLEMENTATION_PROGRESS_AND_ACCEPTANCE_EVIDENCE_2026-10-10.md). This plan is not evidence that all steps are complete. Security experiments run on owned/authorized test machines, with actual evidence; no fabricated successes are acceptable.

The current working source is C:\DVILLIE-main-repairs. Preserve the original three checkouts and existing repair/logo changes. Relevant source anchors include agent/privilege, agent/evidence.py, agent/controller.py, agent/store/db.py, agent/modules/firewall_apply.py, agent/modules/sandbox.py, agent/update/tuf.py, agent/cpu_contract.py and installer scripts. Inspect each before editing; these are candidate integration points, not a guarantee the source already satisfies the design.

## Step 1 — Reconcile project and installed baseline

**Work:** record source revision, pending changes, dependency inputs, configuration, existing audit findings and installed artifact identity. Compare source/deployment differences read-only. Preserve a recoverable source/state snapshot before modifications.

**Output:** a baseline report distinguishing current source, historical records and actual runtime facts.

**Exit:** each planned repair has a current source anchor; no original checkout or unrelated changes are overwritten. Unknown runtime status remains unknown.

## Step 2 — Agree measurable delivery scope

**Work:** select supported Windows editions/builds and first user workflows. Approve automatic action classes, target scope, data retention and benchmark populations. Define how numerical resource/disruption budgets will be measured and frozen before held-out evaluation.

**Output:** approved charter/requirements revision and decision record.

**Exit:** process-level versus path-level containment semantics are explicit; wider machine isolation is not implied.

## Step 3 — Trace requirements to risks and tests

**Work:** map every requirement to threat, source location, planned test and evidence owner. Incorporate the installation/helper holds and existing source repairs.

**Output:** updated traceability matrix and prioritized backlog.

**Exit:** privilege, journal, recovery and truthful verification work precedes advanced automation.

## Step 4 — Specify mutation and recovery state

**Work:** define operation/resource identity, serialization, ownership, preconditions, intent durability, outcome states and conditional restoration. Write a TLA+ specification covering concurrent callers, crashes and external edits.

**Output:** reviewed state specification, assumptions and transition-to-code mapping.

**Exit:** unauthorized effects, conflicting claims and unsafe restore counterexamples are addressed. Model checking is labeled model evidence, not actual Windows enforcement.

## Step 5 — Resolve trusted package staging

**Work:** inventory/pin trusted runtime and dependencies; validate provenance and hashes; stage a protected artifact without elevating a mutable checkout. Design transactional activation and safe migration of private state.

**Output:** reviewed staging/install design and candidate package manifest.

**Exit:** replacement, unsafe ancestors and reparse inputs are rejected. Changing permissions is never treated as authenticity proof.

## Step 6 — Implement durable operation journal

**Work:** add transactional intent and state records, cross-process resource claims, corruption detection and startup reconciliation. Preserve unresolved records during schema migration. Reserve recovery capacity.

**Output:** journal/recovery implementation tied to existing controller/store paths.

**Exit:** real process interruptions at transaction boundaries produce correct reconciliation without blind replay; unrelated external edits survive.

## Step 7 — Implement OS-authenticated helper transport

**Work:** implement the actual local pipe server/client using explicit rights, remote rejection, protected service identity and bounded frames. Obtain caller identity through Windows mechanisms and always revert impersonation correctly.

**Output:** protected transport and deployment configuration.

**Exit:** unauthorized callers and pipe-squatting/instance-creation cases cannot obtain mutation authority. Token-only loopback remains unavailable for production.

## Step 8 — Implement protected authorization

**Work:** define server-owned policy, scoped grants, expiry/revocation and request binding. Authenticate identity independently from permission to act. Review same-user compromised-GUI scenarios and high-impact approval mediation.

**Output:** policy decision point and immutable authorization/audit references.

**Exit:** a malicious same-user client with a valid payload cannot authorize itself. If the trusted approval boundary is unresolved, affected automation remains observation/proposal only.

## Step 9 — Connect restrict_network only

**Work:** integrate the currently defined narrow operation with journal, precondition checks and ownership markers. Preserve existing closed parameter validation. Revalidate executable identity and state immediately before mutation.

**Output:** one complete end-to-end operation; no generic privileged shell.

**Exit:** unsupported operations/parameters cause no host change. Additional ASR/CFA operations are not smuggled through this contract.

## Step 10 — Implement independent verification and restoration

**Work:** read effective policy independently and test actual connection behavior for the intended scope. Mark applied versus verified separately. Compare owned current state before restoring.

**Output:** verifier/recovery records and GUI states.

**Exit:** executor success with continued traffic is not reported protected; partial reads/errors remain unknown; restoration preserves external changes.

## Step 11 — Validate network coverage on real Windows

**Work:** exercise IPv4/IPv6, existing/new TCP/UDP/QUIC workloads, direct/VPN/proxy routes, children/replacement and competing policy. Generate constrained interaction coverage and mandatory race cases.

**Output:** real workload/traffic evidence by exact build and adapter semantics.

**Exit:** release claims cover only tested semantics. If path rules cannot achieve desired process-instance behavior, resolve with a reviewed platform adapter and fresh tests rather than relabeling the same rule.

## Step 12 — Upgrade evidence and finding lifecycle

**Work:** implement versioned event/target schemas, timestamps, health and provenance; separate findings/hypotheses from facts. Show gaps and uncertain applicability.

**Output:** evidence store, health views and factual reports.

**Exit:** missing data, PID reuse and stale feeds cannot become confident actionable facts.

## Step 13 — Add path-based deterministic prioritization

**Work:** build an evidence-bearing asset/permission graph. Choose least-disruptive controls covering supported consequential paths. Keep unknown edges and path coverage visible.

**Output:** explainable prioritizer using the proposed loss/graph formulation.

**Exit:** each recommendation references actual events and a feasible action; no invented attack probability or actor attribution.

## Step 14 — Resolve privacy and performance admission

**Work:** inspect actual stored/exported fields and outbound traffic. Implement approved retention/redaction and process-tree accounting, bounded queues and priority recovery. Measure real foreground tasks, battery/resource cost and offline behavior.

**Output:** privacy evidence and agreed performance baseline.

**Exit:** sharing settings hold; dropped data is visible; optional tasks yield before essential recovery. Freeze acceptance thresholds before final evaluation.

## Step 15 — Admit optional AI

**Work:** select exact free/license-compatible model/runtime; isolate it; enforce structured proposals and deterministic gates. Evaluate evidence fidelity, poisoning/injection, calibration and actual user benefit on held-out real data.

**Output:** model card, artifact manifest, evaluation and promotion/rollback decision.

**Exit:** the model cannot issue privileged commands or expand scope. If it adds cost without benefit, retain deterministic protection.

## Step 16 — Add cryptographic inventory and migration adapters

**Work:** inventory real cryptographic assets; probe installed providers; implement a standards-based supported protocol; verify actual exchange and authentication separately. Test downgrade, invalid inputs and key lifecycle.

**Output:** CBOM-compatible inventory and measured peer/build compatibility.

**Exit:** PQ capability labels match negotiated evidence. Do not rewrite vendor protocols or claim PQ authentication from hybrid exchange alone.

## Step 17 — Add authorized ethical assessment workspace

**Work:** implement authority/scope records, permitted tests, rate limits, time windows, credential isolation, per-request DNS/redirect checks and cancellation. Start with bounded inventory/passive findings before active tests.

**Output:** isolated assessment engine and scoped reports.

**Exit:** every real action remains in authorized scope; stopping prevents new actions and reports in-flight work honestly. External tool licenses and exact artifacts pass review.

## Step 18 — Validate product experience

**Work:** connect lifecycle/evidence/recovery states to the existing GUI. Preserve approved branding. Implement/test keyboard access, Narrator support, scaling and reduced motion; analyze actual flashing.

**Output:** usable end-to-end journeys and accessibility evidence.

**Exit:** decoration never substitutes for protection status, essential actions have accessible alternatives and hidden animation does not exceed budget.

## Step 19 — Harden updates and operations

**Work:** complete reviewed TUF/provenance/key lifecycle, protected activation, compatible rollback and safe uninstall. Test recovery and publish operator/support/disclosure procedures.

**Output:** trusted release candidate with manifest, SBOM/notices, recovery instructions and known issues.

**Exit:** no elevated mutable inputs; no stale/substituted update accepted; uninstall restores owned changes only.

## Step 20 — Evaluate, pilot and release

**Work:** run predefined real benign/security workloads and free-baseline comparisons. Report all adverse outcomes, uncertainty, excluded environments and failed checks. Start observation-only pilot, then narrow enforcement pilot, then broader supported release after evidence review.

**Output:** acceptance report and explicit release decision.

**Exit:** no unauthorized mutation, destructive restore, scope escape, secret leakage or falsely verified protection remains in released capabilities. Advanced features that fail are excluded transparently while useful validated protection may proceed.

## Dependencies and change sequence

Steps 1–5 precede elevated runtime work. Steps 6–10 form the trusted mutation lifecycle. Step 11 establishes network behavior; steps 12–14 establish reliable evidence and resource/privacy admission. AI and assessment depend on these boundaries. Crypto inventory may be researched in parallel but release integration still depends on trusted updates and validation.

Use small reviewable increments. Every increment supplies source changes, relevant tests, actual results, recovery behavior and documentation updates. No fixed calendar or staffing estimate is invented; estimate each work package after baseline and test-machine availability are established.

## Stop, fallback and continuity

STOP cancels further initiated work and preserves unresolved outcomes for reconciliation. When a case fails, identify its counterexample, revise the mechanism and rerun only affected checks plus necessary regression coverage. Do not repeatedly run a failing design unchanged.

The success condition is an accepted, functioning, measured capability for declared scope—not the disappearance of warnings through wording.
