# D'Vielle — Ethical Assessment Rules of Engagement

Version 1.0 • 10 October 2026 • Proposed assessment policy and execution procedure

## Purpose and authorization

Assessment capability exists to find and resolve weaknesses in owned or explicitly authorized assets. A general request to improve D'Vielle is not authorization to test unrelated internet systems. Internet research access is not assessment scope.

The assessment record names the asset owner/authorizing party, evidence of authority, permitted targets, exclusions, allowed test classes, schedule, rate/concurrency limits, stop conditions, data handling and reporting recipients. Record actual facts; never fabricate an authorization signature.

## Scope semantics

Targets include exact domain/address/application identifiers and relevant ports/protocols. Resolve DNS at execution time and validate the resulting address; recheck after redirect or rebinding. Third-party identity/payment/CDN services are not automatically included because an authorized website uses them.

Define whether subdomains, resolved infrastructure and authenticated application paths are included. Default ambiguity is exclusion until clarified. An allowlist is enforced on every outgoing action, not only on the initial scan setup.

## Permitted sequence

Begin with inventory and passive review. Confirm component/version applicability and normal operation. Introduce active checks only under their authorized class and risk controls. Keep tests bounded and cancelable. Use separate credentials scoped to the assessment; isolate secrets from ordinary evidence/model prompts.

Tool settings are not the entire boundary. The wrapper independently validates scope and behavior. ZAP context/scope settings help configure web assessments but require integration verification.

## Prohibited default behavior

Do not initiate disruption, persistence, credential collection, broad exploitation, data destruction or privilege expansion outside the accepted test scope. Do not download/run uncontrolled attack packs or treat all tests in a free repository as safe. A destructive case requires its own explicit controlled environment and authorization.

Do not export third-party private content when minimal evidence is sufficient. Do not submit findings/data to external platforms automatically.

## Stop and incident handling

A user stop, expired scope, unexpected target, excessive errors, resource budget violation or suspected unintended effect stops new actions. Retain in-flight state and reconcile actual outcomes. Stop is not retroactive cancellation of a packet already sent.

If unintended behavior occurs, preserve minimal evidence, contain through accepted policy, notify through the authorized reporting process and use the incident-response plan. Do not silently delete evidence or repeat the same failing test.

## Evidence and reporting

A report names scope/version/time, methods, actual observations, affected assets, potential applicability, confirmed behavior, benign alternatives, severity reasoning, remediation and retest requirements. Include unavailable coverage and failed/stopped cases.

A version match is an applicability lead; an exploitable claim requires corresponding evidence. A simulated outcome cannot be presented as an actual target compromise. Reports do not include invented successful exploit results.

## Closure and remediation

Prioritize actionable root causes and preserve normal service. Retest within the accepted scope after repair, record the actual result and identify residual exposure. Reports distinguish repaired source from deployed fix.

These rules describe future product behavior; no external scans, active tests, disclosures or messages were performed in this documentation task. Supporting primary reference: [NIST technical security assessment guide](https://csrc.nist.gov/pubs/sp/800/115/final), previously researched in the companion dossier.
