# D'Vielle security advancement: research and engineering case

Date: 2026-10-10. Research only. No security controls, services, installers,
scanners or application code were changed by this research task.

This dossier separates established platform behavior, proposed architecture,
current project evidence and experiments still required. It does not establish
that the application is world-leading or that proposed protections are deployed.

## Product objective and success evidence

Build free everyday protection and an optional authorized assessment workspace
around a common evidence/action/recovery system. Each finding must connect to
an affected asset, evidence, authorization, repair, independent verification and
recovery. A professional scanner and a consumer guardian have different workloads
and permissions; they share evidence formats, not unrestricted execution.

Success must be evaluated against declared competitors/configurations, realistic
benign workloads, independently held assessment cases and reproducible results.
Measure prevention, detection delay, false interventions, assessment accuracy,
recoverability, performance and coverage separately. No current comparison data
exists in this dossier. Numerical product targets require measured baselines.

## Questions, logical answers and required proof

| Question | Proposed resolution | Required evidence before claiming success |
|---|---|---|
| How does the product identify consequential weaknesses? | Connect process identity, signer, installed version, effective privileges, persistence, exposed services and sensitive resources in an attack graph. Prioritize interrupting reachable paths. | Trace independently known paths; record missing observations; verify proposed changes remove the specified path while preserving legitimate workflows. |
| What is sufficient evidence for autonomous intervention? | Use fresh source observations, explicit preauthorized policy, validated target identity and bounded effects. Preserve provenance and distinguish missing evidence from benign evidence. | Held-out malicious and ordinary workloads; calibration; intervention harm and missed-threat measurements. |
| Can confidence alone justify blocking? | No. Confidence must be calibrated and combined with consequence, scope, reversibility and authorization. | Validate calibration under changed software versions and adversarial inputs; do not interpret model scores as measured probabilities by default. |
| What if two agents repair the same subject? | One durable claim per subject/action, an idempotency key and ownership-checked finalization. | Concurrent real-process tests; crash at each state transition; observe no duplicate side effects. |
| What if a setting changes after assessment? | Revalidate prerequisites and target identity immediately before execution; compare state with the authorized plan. | Concurrent external policy changes, replaced executable, renamed paths and reparse-point races. |
| What if the action succeeds but its result is lost? | Record intent before execution; reserve ambiguous outcomes; reconcile observed state instead of blindly retrying. | Kill/power-loss tests across dispatch, execution and finalization; recover exact observed outcomes. |
| How is a privileged caller authenticated? | OS-authenticated local IPC, explicit pipe rights, narrow schemas, protected authorization records and expiring one-use requests. Validate caller identity and authority separately. | Wrong-user, wrong-session, remote client, replay, spoofed server, malformed request and oversized message tests. |
| Can another process act under the same user's identity? | User identity alone does not prove approved application intent. Design a protected approval broker and operation-bound authorization; minimize ambient authority. | Same-user malicious-client tests; copied secrets; modified private config; impersonation failures. |
| Can the network block be overridden or miss another route? | Inspect effective WFP/firewall behavior and filter conflicts, then independently test relevant paths. | IPv4/IPv6, TCP/UDP, QUIC, VPN adapters, proxies, DNS variants, existing connections, restart and service-failure behavior. |
| How is file quarantine reversible? | Prefer supported antivirus quarantine interfaces; preserve original identity and provenance and define explicit release. | Actual restore into an isolated environment; interruption, permission denial, concurrent file changes and false-positive recovery. |
| How does the AI resist malicious evidence? | Separate data and instructions; no authority from tool output; typed adapters; policy-controlled capabilities; isolated analysis. | Malicious documents/logs, forged recommendations, tool-result injections, poisoned memory and attempts to expand targets/permissions. |
| Can learning become an allowlist attack? | Do not promote dismissed alerts directly to trust. Version candidate policies, evaluate independently and require signed promotion. | Poisoning/evasion exercises; rollback; repeated malicious feedback; retention of previously detected attack classes. |
| Can assessment expand beyond authorization? | Bind jobs to authorized targets and techniques; revalidate redirects and resolution changes; deny out-of-scope discovery expansion. | Redirect, DNS rebinding, IPv6, cloud/shared-host and expired-authorization cases; verify zero out-of-scope active tests. |
| Does a vulnerable package mean this installation is exploitable? | Preserve version/configuration/exposure evidence and advisory matching semantics; distinguish affected, reachable, confirmed and unassessed. | Independent version checks, vendor advisory comparison, corrected-version retest and explicitly authorized verification. |
| Can a kernel or firmware attacker falsify local health? | Layer supported boot/driver protections with independent recovery and appropriate external evidence. | Separate pre-compromise prevention and post-compromise recovery evidence; never treat local hash reports alone as complete attestation. |
| What counts as a recoverable backup? | Encrypted versioned copies in a failure domain the threatened process cannot freely destroy; independently usable recovery keys. | Restore and validate actual files after an isolated destructive exercise; device/key loss; disconnected/offline operation. |
| Does PQC key exchange cover authentication? | Track negotiated key establishment, peer authentication, artifact signatures and stored-data encryption separately. | Protocol interoperability, certificate validation, downgrade/malformed-message tests and explicit per-layer coverage records. |
| Can third-party software be quantum-upgraded automatically? | Use supported, vendor-specific capability discovery and migration adapters; test and verify each protocol/application. | Real client/server negotiation and application behavior; no status inferred solely from a installed library version. |
| How does crypto advance safely? | Crypto-agile providers, versioned policy, standard-compliant protocols, signed upgrades, key rotation and recovery. | NIST vectors, interoperability, current errata, malformed inputs, implementation review and performance measurements. |
| How does the free product remain usable? | Event-driven resident collection; optional assessment modules; bounded work queues; idle scheduling; local essential protection. | Measure process trees, helper costs, startup/application latency, battery/disk/network load and degraded-host behavior. |
| Can free components be redistributed? | Keep a component/feed/license register, use compatible licenses and official-download adapters where bundling is not permitted. | Actual selected-version license review, transitive dependencies, attribution and redistribution obligations. |
| What earns a world-leading claim? | Independently repeatable comparisons, disclosed misses and false positives, recovery results and public measurement methods. | External review and equivalent-condition results. A research dossier cannot substitute for these experiments. |

## Architecture and trust boundaries

1. Unprivileged collectors produce timestamped, provenance-bearing observations.
2. Evidence storage preserves source identity, freshness and collection failures.
3. A reasoning layer builds hypotheses and action proposals, not privileged commands.
4. A separate policy engine verifies authorization, scope and prerequisites.
5. A narrow privileged service executes validated operations and records effects.
6. Independent verification observes actual outcomes; it does not trust command success.
7. Recovery reconciles partial changes, restores owned state and keeps ambiguous
   effects visible rather than releasing them for an automatic retry.

Proposed decision objective: choose authorized actions minimizing expected user
harm, including missed threats, false interventions and disruption. Probability
inputs require calibration. EPSS is CVE-level exploitation likelihood in the next
30 days and must not be relabeled as per-device compromise probability.

Local hash-chained logs provide tamper evidence only while their trust material
and checkpoints remain trustworthy. Compromised local signers can sign false
records. Use optional independently retained checkpoints/recovery artifacts and
state this distinction explicitly.

## Three engineering cases to resolve first

### A. Application network containment

Bind an operation to the approved executable identity and explicit destinations,
profiles and address families. Preserve existing policy. Verify actual connection
outcomes using controlled endpoints, including unintended collateral blocking.
Check how existing connections and alternate/proxied routes behave. Keep failed
or uncertain cleanup visible. Evaluate program replacement and child-process
behavior rather than assuming a program-path rule contains every descendant.

### B. Crash-safe protection changes

Capture the original state and desired change durably. Recheck it before mutation.
After interruption, compare effective state with both intended and original state.
Restore only owned changes; do not erase intervening administrator policy.
Treat unavailable observations as a recovery condition, not success.

### C. Verified post-quantum communications

Inventory algorithms and dependencies. Select maintained implementations and
standardized protocol compositions. Verify actual key exchange and authentication
separately, including intermediaries and fallback. Check key persistence, rotation,
entropy handling, malformed inputs, interoperability and current errata. Evaluate
PQC signatures for D'Vielle's application-layer artifacts separately from Windows
Authenticode support. Do not assume OS API availability updates every application.

## Current project anchors

- `agent/privilege/contract.py` defines only `restrict_network`; arbitrary helper
  operations are refused. This is a narrow source contract, not a deployed service.
- `docs/REPAIR_INSTALL_PRIVILEGE_BOUNDARY.md` records protected staging and real
  privileged-service work still required. Its pipe contract is defined-only.
- `docs/REPAIR_WINDOWS_CONTROLS.md` records source/unit verification boundaries and
  the need for actual Windows/packet-level validation.
- `docs/REPAIR_STATUS_2026-10-09.md` distinguishes repaired source from deployment.

No additional host probes, active scans, attack exercises or remediation were run
to support this dossier. Historical unit results do not establish attack efficacy.

## Primary-source register and interpretation

- Microsoft named-pipe security:
  https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
  Generic write also grants create-instance rights; select individual rights.
- Microsoft caller impersonation:
  https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client
  OS identity is obtainable; authorization still requires an application design.
- Microsoft WFP arbitration:
  https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
  Layers, sublayers and action rights affect final decisions; validate effective behavior.
- NIST KEM guidance, final 2025-09-18:
  https://csrc.nist.gov/pubs/sp/800/227/final
  Algorithm selection must be integrated with protocol/key-management requirements.
- NIST PQC discovery/interoperability project:
  https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc
  Discovery and interoperability are separate workstreams; draft lab work is not
  evidence of this product's performance or production deployment.
- Microsoft production PQC announcement, 2025-11-18:
  https://techcommunity.microsoft.com/blog/microsoft-security-blog/post-quantum-cryptography-apis-now-generally-available-on-microsoft-platforms/4469093/replies/4478514
  Production availability is announced for supported platforms; test exact builds
  and consumers. Some documentation still contains older Insider wording.
- NIST ML-KEM and ML-DSA standards/errata:
  https://csrc.nist.gov/pubs/fips/203/final
  https://csrc.nist.gov/pubs/fips/204/final
  Track published corrections and implementation versions.
- OWASP ASVS:
  https://owasp.org/projects/asvs
  Apply relevant requirements to web/API modules; this is not whole-endpoint certification.
- OWASP agentic security:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
  Translate threats into concrete adapter, policy and isolation tests.
- NIST adversarial ML:
  https://csrc.nist.gov/pubs/ai/100/2/e2025/final
  Address poisoning, evasion, abuse and privacy separately.
- NIST cyber resilience:
  https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final
- NIST firmware resilience:
  https://csrc.nist.gov/pubs/sp/800/193/final
- SLSA:
  https://slsa.dev/spec/v1.2/
  Build/source provenance and update-channel security are distinct requirements.
- FIRST EPSS:
  https://www.first.org/epss/
  Free daily API/CSV data; contextual prioritization rather than host compromise prediction.
- Microsoft Sysinternals licensing:
  https://learn.microsoft.com/en-us/sysinternals/license-faq
  Free use does not grant permission to bundle these utilities.

## Research disposition

The architecture above is proposed, not experimentally validated. The next
evidence needed is controlled implementation validation of cases A/B/C followed
by independent assessment and comparative evaluation. Further literature work
should resolve specific unanswered design questions and track changing standards;
repeating broad searches alone cannot establish product superiority.
