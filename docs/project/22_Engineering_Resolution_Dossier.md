# D'Vielle — Engineering Resolution Dossier

Version 1.0 • 10 October 2026 • Proposed solutions with proof obligations

## Purpose

Resolve difficult issues through mechanisms and tests rather than leaving them as vague limitations. Each entry distinguishes a design resolution from proof that it works in this application. The next required work is explicit, and a fallback preserves useful protection.

## Same-user malware and genuine approval

**Problem:** a hostile program may run under the same SID as the GUI. OS caller identity and a user-readable token do not establish genuine approval.

**Resolution:** protect service policy; bind grants to operation/target/scope; keep broad authority out of ordinary writable state; mediate high-impact grants through a reviewed protected approval channel. The service validates policy independently.

**Challenge/proof:** attempt valid requests from hostile same-user clients and replay grants against altered targets. Assess UI spoofing and the selected mediation mechanism. Until the boundary is proven, retain observation or tightly predetermined server policy; do not claim SID checks solve consent.

## Concurrency, crashes and external edits

**Problem:** a successful command can lose its result, while another actor changes the same policy.

**Resolution:** serialize overlapping resource mutations, persist intent before write, retain ownership IDs and reconcile actual state on restart. Restore only owned effects after current-state comparison.

**Proof:** real process interruption at every transaction boundary plus administrator changes. Unknown outcomes remain actionable recovery records. Never remove unknown records merely to unlock further writes.

## Effective network containment

**Problem:** program-path rules may differ from process-instance claims; existing sessions and routes can behave differently.

**Resolution:** specify the exact capability, verify effective policy and actual traffic, and test route/transport/session combinations. If desired semantics need a different WFP adapter, design that adapter explicitly rather than overstating firewall rules.

**Proof:** independent client/server observations on owned machines. Release a narrower supported restriction if broader behavior is unproven.

## Windows Home and management contradictions

**Problem:** Microsoft overview/license tables and feature-availability wording do not present a single simple Home-support story.

**Resolution:** separate policy effectiveness, authoring cmdlets, deployment tooling and entitlements. Current feature documentation says policies are effective on all editions while Home lacks authoring cmdlets; the overview lists Pro and higher in its support/license table. Validate an exact build and confirm rights before shipping an adapter. This discrepancy is recorded, not hidden.

**Fallback:** useful observation and other verified local controls remain available. Windows Sandbox is explicitly unavailable on Home; do not bypass edition checks with unsupported hacks.

## Unknown threats and false interventions

**Resolution:** combine least-privilege controls with evidence-bearing attack paths and base-rate-aware, loss-sensitive decisions. Require actual applicability and calibration. Unknown inputs trigger bounded investigation, not fictional certainty.

**Proof:** held-out real workloads and benign tasks with confidence intervals. Continue researching concrete missed-path counterexamples; do not expand claims without evidence.

## Resource stability

**Resolution:** bound workers/queues, reserve verification/recovery capacity and defer optional models/animation. Account for all child processes and job breakaway.

**Proof:** real foreground tasks, burst loads, sleep/resume and model failures. Queue-stability equations are planning tools, not measured responsiveness.

## Quantum migration

**Resolution:** inventory cryptographic assets; use standardized protocols/providers; separate exchange from authentication and test peers/rotation/downgrade.

**Proof:** actual handshake/provider records. No custom physics metaphor substitutes for cryptographic engineering.

## Free ecosystem and legal access

**Resolution:** select license-compatible artifacts and approved free APIs; exclude restricted feeds from core dependencies. Sysinternals remains externally obtained, URLhaus remains conditional, EPSS bulk uses CSV. Do not evade access controls to collect research or bypass licensing.

**Proof:** artifact/license ledger and actual query/data-flow review. Resolve inaccessible primary legal texts before making specific compliance claims; free price is not an exemption analysis.

## Deep compromise and recovery

**Resolution:** expose trust uncertainty, protect/detect/recover at appropriate platform layers and provide independent vendor/offline recovery paths. A locally compromised kernel can undermine local observation.

**Proof:** platform/vendor-specific restore and evidence validation. Do not let an unverifiable local status become an all-safe assertion.

## Research continuation rule

A remaining question gets a precise hypothesis, credible primary sources, competing explanations, selected mechanism and falsifiable test. Search continues when evidence could change the decision. Implementation results and new counterexamples then guide the next research cycle. No entire-web completeness or universal solved-security claim is invented.
