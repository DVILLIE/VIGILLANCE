# D'Vielle — System Architecture and Trust Boundaries

Version 1.0 • 10 October 2026 • Proposed detailed design

## Baseline and deployment separation

The repair checkout contains GUI, collectors, intelligence, policy/controller, storage, update and privilege modules. The installation repair record explicitly holds elevated resident execution and describes the production helper pipe as defined_only. This design extends that source baseline; it does not claim a running privileged service exists.

The three original checkouts remain historical inputs. The repair checkout is the working design location. A release must later identify its exact source revision and artifact, rather than launching whichever checkout happens to be present.

## Logical components

Collectors obtain bounded OS observations. The evidence layer preserves source/freshness and process identity. The analysis layer correlates evidence and produces proposals. The policy layer authorizes typed actions under user policy. The broker submits validated requests to a protected service. The executor applies a narrow change. An independent verifier reads resulting state and behavior. Recovery reconciles durable intent and actual owned effects.

The GUI reads these records and submits user decisions. It never gains administrator authority merely because it displays a button. Optional models and assessment tools run in restricted worker processes, outside the privileged executor.

## Trust boundaries

| Boundary | Untrusted input | Required defense |
|---|---|---|
| OS observations -> evidence | Missing, stale or adversarially influenced events | Provenance, health, age, identity and corroboration |
| Evidence -> model | Prompt-like text, malicious filenames/URLs | Treat content as data; structured output with no authority |
| GUI/client -> service | Same-user malware, malformed requests, replay | OS authentication plus independent scoped authorization |
| Download -> activation | Compromised mirror, old metadata, substituted binary | Trusted-root verification, version/freshness and hash checks |
| Assessment -> target | Redirect, DNS change, scope drift | Per-action target validation and cancellation |
| Journal -> recovery | Corruption, partial writes, external policy edit | Protected ownership, transactional persistence and comparison |

## Privileged service design

Install service code and runtime from a trusted artifact into a protected root. Use explicit pipe rights, reject remote clients, prevent pipe-instance creation by ordinary clients and verify client identity through Windows mechanisms. Limit operation rights and account privileges; select the service account based on tested required APIs.

Do not mistake caller SID, executable signature or a secret stored in user-writable state for complete approval protection. The service needs protected policy specifying permitted operations and bounded scopes. High-impact approval must be mediated through a reviewed mechanism whose authority cannot be broadened by a compromised same-user GUI. If this boundary is not established, privileged automation stays disabled.

## State ownership and concurrency

Each mutation has an operation ID, resource claim, policy version, precondition digest and ownership marker. Serialize overlapping resources across processes. Expiry ends permission to initiate new work, but does not erase an applied effect. Use actual-state reconciliation after failures; no generic “retry everything” loop.

For network restriction, distinguish a path-wide firewall rule from process-instance containment. Child processes, executable replacement, VPN/proxy routing and existing sessions require measured behavior. The adapter reports its precise supported scope.

## Degradation and resilience

Lost inference leaves deterministic observation and accepted fixed policies available. Lost storage prevents new mutations. Lost verification leaves an unknown outcome. Lost service removes action capability while the GUI remains usable. Suspected kernel/firmware compromise changes the trust assessment; recovery may require independent offline tooling or vendor recovery rather than trusting local self-report.

## Evolution

Initially reuse and harden existing agent/privilege, controller, evidence and storage boundaries. Avoid adding a second competing policy authority. Define interfaces before choosing a new AI framework or scanner. Every new adapter adds capabilities, ownership rules, failure behavior and tests. Architectural decisions are recorded in the governance document.

References: [Windows pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [WFP arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration), [NIST cyber resilience](https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final).
