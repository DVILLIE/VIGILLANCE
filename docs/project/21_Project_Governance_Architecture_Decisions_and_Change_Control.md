# D'Vielle — Project Governance, Architecture Decisions and Change Control

Version 1.0 • 10 October 2026 • Proposed governance baseline

## Authority and decision record

The human owner controls product direction, consequential authority, publication and deployment. Engineering prepares concrete reviewable changes and evidence. Security/privacy/quality responsibilities may be fulfilled by reviewers as the project grows; no appointed team is invented.

A decision record includes problem, evidence, alternatives, selected approach, consequences, owner approval status, source/document version and acceptance tests. Implementation approval and release approval are distinct. Current documentation authorization does not permit application modification.

## Initial proposed decisions

**ADR-01 — Local-first free core.** Select local evidence and optional external enrichment. Alternative: mandatory cloud processing. Consequences: lower compulsory service dependence and better privacy, but device resource admission and offline update behavior must be designed.

**ADR-02 — Separate intelligence and authority.** Select model proposals plus deterministic policy/restricted executor. Alternative: elevated autonomous tool agent. Consequences: narrower integration contracts and explicit operation onboarding; prevents fluent untrusted output from granting authority.

**ADR-03 — Durable ownership-based recovery.** Select intent journal and actual-state reconciliation. Alternative: best-effort commands and blanket rollback. Consequences: more lifecycle complexity, but safe handling of crashes and administrator changes.

**ADR-04 — Authenticated protected helper.** Select OS-authenticated IPC and server-owned scoped policy. Alternative: token-only loopback or elevated resident GUI. Consequences: protected installation and genuine approval boundary must be established first.

**ADR-05 — Scope-dependent verification.** Select effective-state and real behavior checks. Alternative: API return code as protection proof. Consequences: independent observer/route matrix and truthful unsupported states.

**ADR-06 — Standards-based cryptographic agility.** Select inventory and supported adapters. Alternative: custom quantum encryption. Consequences: peer/provider compatibility and authentication are reviewed separately.

**ADR-07 — Version-controlled project documents.** Select readable Markdown with named documents and traceability. Alternative: detached unversioned files. Consequences: evidence/results remain attached to source history; publication formats can be exported separately when requested.

All entries are Proposed for the advancement baseline. No signature or approval is fabricated.

## Change control

Routine documentation clarification may proceed within authorization. New operation, new privilege, expanded assessment scope, changed retention/export, remote model processing, update trust change or destructive migration requires an explicit reviewed decision. Existing accepted authority is not repeatedly requested without reason.

A change proposal states user need, current source evidence, options, compatibility, data flow, rights, recovery and validation. The delivered review package contains final changes and actual results, not a plan awaiting basic implementation.

## Backlog and delivery discipline

Prioritize critical trust boundaries and recovery ahead of feature breadth. Resolve a defect at its root cause and record counterexamples. Reuse existing components where sound; do not accumulate competing policy engines.

Use milestones from the implementation plan rather than guessed dates. Estimate after source/baseline review and test environment availability. Record dependency blockers, the action needed to resolve them and a useful narrower fallback.

## Claims and publication

Publish supported capabilities with tested scope and evidence. Distinguish proposed, implemented, deployed and verified. Naming a recognized standard or tool does not transfer its reputation to the product.

A comparative leadership claim needs current real evidence under declared benchmarks, including adverse results and resource cost. No fake reviews, simulated deployment results or invented endorsements are permitted.

## Document control

Version 1.0 identifies this authored baseline. Future revisions record concrete changes and approval separately. Maintain the master index, requirements IDs, cross-links and source access status. Historical repair/design records remain preserved as supporting evidence; this suite does not silently supersede them.
