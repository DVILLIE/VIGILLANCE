# D'Vielle — Product Requirements and User Journeys

Version 1.0 • 10 October 2026 • Proposed product specification

## Users and problems

An everyday user needs safe browsing, reliable work and understandable decisions without constant alerts. A technically experienced user needs precise evidence and control over automatic actions. An authorized assessor needs explicit scope, repeatable findings and proof that tests stayed inside it. A device administrator needs compatibility, recovery and protection against a malicious caller abusing the application.

The application must serve inexperienced users without hiding important uncertainty from experienced users.

## Required user journeys

**First use.** The user sees the publisher/version, local-first data explanation and a posture summary. D'Vielle identifies available sensors and controls without changing Windows policy. It explains missing prerequisites and offers an understandable choice of observation or individually supported automatic actions. Observation remains useful if privilege or internet access is unavailable.

**Investigate a finding.** The finding shows what was observed, when, which component supplied it, the protected asset involved, why the event matters, benign alternatives, recommended action and current coverage. An affected package is not called exploitable without supporting evidence. The user can inspect the original source and export a redacted report.

**Contain a process.** The user sees the executable identity, intended network scope, expected disruption and recovery procedure. A previously granted policy may authorize this without a repeated prompt. The operation displays pending, applied and verified as distinct states. Unknown outcome produces a recovery view rather than a success badge.

**Recover daily work.** The user can review owned changes and request restoration. The application first compares actual current policy with its journal. If an administrator changed the policy meanwhile, restoration preserves the external change and explains the conflict.

**Run an ethical assessment.** The user identifies asset authority, allowed targets, permitted tests, exclusions, time window and stop conditions. The system validates scope at every outgoing action, including redirects and DNS changes. A report distinguishes observation, confirmed behavior, version applicability and unverified hypotheses.

## Product requirements

| ID | Requirement | Priority |
|---|---|---|
| PR-01 | Provide useful local observation without mandatory registration or subscription | Essential |
| PR-02 | Show coverage health and evidence age alongside findings | Essential |
| PR-03 | Explain consequential actions and preserve a durable work log | Essential |
| PR-04 | Permit only individually authorized, verified and recoverable automatic operations | Essential |
| PR-05 | Preserve unrelated Windows and third-party protection | Essential |
| PR-06 | Offer redacted export and explicit data deletion controls | Essential |
| PR-07 | Include keyboard use, readable text, reduced motion and accessible status descriptions | Essential |
| PR-08 | Isolate authorized assessment from everyday protection authority | Essential before assessments |
| PR-09 | Inventory cryptography and report actual migration/negotiation status | Advanced |
| PR-10 | Use calibrated evidence analysis and path-based prioritization | Advanced |

## Behavior and language

Use “Observed”, “Policy applied”, “Effect verified”, “Recovery required” and “Coverage unavailable” accurately. A glowing logo indicates application activity only. Network animation must not imply verified traffic flow. “Unknown” must remain available rather than forcing an attractive green state.

Avoid describing Microsoft or another application's telemetry as theft solely because a connection occurred. Present destination, process, declared purpose where known, applicable setting and measured behavior. Malice and actor attribution need separate evidence.

## Acceptance and prioritization

A journey is complete only when its error, interruption and recovery paths are usable. Product acceptance covers an actual benign task through the journey, not merely the existence of a screen. Initial usability observations may inform improvements, but are not statistically representative adoption evidence.

Security-critical requirements precede decorative enhancements and broad tool integration. New requested features must identify the user problem, data needed, authority needed, compatibility effect and validation burden. The change-control procedure prevents an appealing feature from bypassing the trust boundary.

## Current baseline

The existing Python GUI, logo and network views remain preserved. This PRD describes desired behavior, not a verified inventory of implemented screens. Source repairs and held deployment boundaries are recorded in the existing repair documents. No production rollout is claimed.
