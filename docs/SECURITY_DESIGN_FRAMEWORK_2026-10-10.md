# D'Vielle: intelligent protection design framework

Date: 2026-10-10. Status: proposed architecture for joint review; application implementation is not authorized in this research phase. Companion: SECURITY_ADVANCEMENT_RESEARCH_2026-10-10.md.

## Product decision

Build a free, local-first Windows guardian that interrupts consequential attack paths, preserves daily work, explains its decisions and proves recovery. Provide an optional ethical assessment workspace for explicitly authorized assets. Both share evidence; the assessment workspace does not inherit unrestricted administrator authority.

Replace a universal marketing score with a published comparison: attack paths prevented, missed attacks, false interventions, recovery correctness, privacy, resource overhead and accessibility. Pursue leadership on these dimensions together. A faster detector that destroys a user's work is a worse product.

## Architecture and contracts

Collectors -> provenance-bearing evidence -> inference -> deterministic authorization -> restricted executor -> independent outcome verification -> recovery journal.

| Component | Required contract |
|---|---|
| Collectors | Unprivileged where possible; bounded queues; report sensor health, source, timestamps and missing coverage |
| Evidence store | Event identity, host identity, process creation identity, executable identity, observed facts, provenance and retention policy; secrets excluded by default |
| Reasoner | Propose hypotheses and actions; cite evidence; express unknowns; cannot issue shell commands to a privileged service |
| Policy engine | Validate operation, target, user authorization, freshness, resource budget and recovery prerequisites independently of model text |
| Executor | Narrow typed operations, authenticated caller, protected executable/configuration and operation-specific rights |
| Verifier | Read actual resulting state; distinguish requested, applied, verified, failed and unknown outcomes |
| Recovery | Durable intent before mutation; restore only changes owned by this operation, subject to current-state comparison |

Existing project records describe the privileged helper as defined_only. This framework does not treat the current application as an already deployed enforcement platform. Start with the documented restrict_network boundary; expand its operation set only after individual contracts and tests are accepted.

## Mathematics: choosing useful interventions

Let H mean a harmful event, E the observed evidence, a an action, and L(a,H) the harm to the user including disruption, residual attack damage and recovery cost.

Posterior odds = prior odds x P(E|H)/P(E|not H).

This is a design equation, not a supplied probability estimate. Joint evidence likelihoods require calibration on real labeled observations. Do not multiply correlated alerts as if independent. An executable reputation alert and a signature alert may share the same source.

Choose the authorized feasible action minimizing expected loss:

a* = argmin_a sum_h P(h|E) L(a,h).

Feasibility requires authorization, bounded scope, supported enforcement, fresh target identity and a recovery plan. Confidence alone never grants permission. If loss estimates or calibration are insufficient, gather more evidence or propose an action for review. Urgent containment may run automatically only under a previously accepted policy.

For a binary containment choice, let C_FP be benign disruption cost and C_FN the preventable harm from not containing a malicious event. Under those simplifying assumptions, contain when p > C_FP/(C_FP+C_FN). Include containment failure and malicious disruption costs in the full loss model before operational use. Thresholds therefore vary by action: isolating one process differs from disconnecting the entire machine.

Evaluate precision using the deployment base rate pi:

PPV = sensitivity*pi / [sensitivity*pi + false_positive_rate*(1-pi)].

Estimate those inputs separately by user/workload group. A balanced laboratory dataset cannot establish everyday precision. Avoid a single opaque risk number.

## Graph theory: interrupt paths rather than chase alerts

Represent observed assets, identities, permissions and communication as a graph. Label each edge with evidence, age, uncertainty and a control capable of removing it. For every protected goal, identify currently evidenced routes from possible entry points.

Proposed planning formulation: minimize sum_j c_j*x_j, subject to every enumerated harmful path containing at least one selected control. Here c_j includes user disruption and maintenance cost; x_j is binary. Controls covering several edges require a set-cover formulation rather than assuming a simple minimum cut.

Unknown paths remain explicit. Refresh the graph after changes, prioritize independently supported paths, and verify the selected control actually removes the intended capability. A solution optimal for an incomplete graph is not proof of complete protection.

## Logic: make autonomy auditable

Proposed state machine:

Observed -> Proposed -> Authorized -> Claimed -> IntentDurable -> Applied -> Verified -> Released.

Failures enter Rejected, Failed, OutcomeUnknown or RecoveryRequired. After a crash, reconcile the journal against actual state before another mutation. Never retry an unknown non-idempotent operation blindly.

Invariants for a TLA+ specification and later implementation checks:

1. Every applied mutation has a matching durable intent and valid authorization for that exact target.
2. At most one active claim owns a resource mutation; claim expiry does not erase a possibly applied effect.
3. Executable/process identity and relevant policy state are revalidated immediately before mutation.
4. Applied does not imply Verified. Verification must establish the operation's postcondition.
5. Restore touches only owned changes and refuses to overwrite intervening user/administrator changes.
6. Untrusted documents, websites and model responses cannot expand an operation's authority.

Use TLC to explore a finite state model with concurrent callers, crashes and external edits. Review the assumptions, then map every transition to code and real integration tests. Checking a model is not automatically checking its implementation. [TLA+ tools](https://lamport.azurewebsites.net/tla/toolbox.html).

## Combinations and event order: economical testing

Proposed network-containment factors:

| Factor | Levels |
|---|---|
| Address family | IPv4, IPv6 |
| Connection age | Existing, new |
| Transport | TCP, UDP, QUIC |
| Route | Direct, VPN, proxy |
| Process relation | Original, child, replaced executable |
| Policy interference | None, user change, competing allow, competing block |
| Crash point | Before write, after write, after verification |
| Caller | Authorized, unauthorized, stale authorization |

The unconstrained Cartesian product is 2*2*3*3*3*4*3*3 = 3,888 configurations. This is a planning calculation, not executed tests. Record infeasible combinations explicitly; encode an actual QUIC application workload rather than treating QUIC and UDP as independent network layers.

Use constrained 3-way covering arrays for initial interaction coverage; increase strength for critical coupled factors. Mandatory targeted cases remain mandatory regardless of array membership: existing QUIC connection through VPN, executable replacement between authorization and execution, hostile same-user caller, administrator policy edit during recovery, and crash after apply before journal confirmation. Test relevant event orders separately. No generated array size is claimed before generation and coverage measurement.

[NIST ACTS](https://csrc.nist.gov/Projects/Automated-Combinatorial-Testing-for-Software) provides free public-domain tools, although obtaining its download link currently requires a request. No request has been sent. Combinatorial coverage is not exhaustive coverage of all attacker behavior.

## Statistics: know what passing establishes

Report prevention, detection latency, false interventions per benign task/hour, recovery outcomes and overhead with denominators and uncertainty. Predefine sampling, labels and acceptance criteria before evaluation; separate tuning data from held-out evaluation.

For zero failures in n independent representative Bernoulli trials, the one-sided 95% exact upper bound is p_upper = 1 - 0.05^(1/n). Solving for a desired bound gives n >= ceil(log(0.05)/log(1-p_target)).

| Proposed upper failure-rate bound | Required zero-failure trials |
|---|---:|
| 1% | 299 |
| 0.1% | 2,995 |
| 0.01% | 29,956 |

These are analytically calculated sample requirements, not application results. Repeating one task thousands of times does not establish population representativeness. Correlated runs require analysis at the independent workload/device cluster level. Report failures with exact intervals rather than discarding unsuccessful runs. Repeatedly inspecting results and stopping opportunistically invalidates a fixed-sample interpretation; predeclare the evaluation or use an appropriate sequential procedure.

The zero-failure expression follows directly from P(0 failures)=(1-p)^n. [NIST exact binomial confidence limits](https://itl.nist.gov/div898/software/dataplot/refman2/auxillar/exacbino.htm).

## Physics and quantum-resistant engineering

Use quantum-computing knowledge to choose cryptography, not decorative claims. Post-quantum algorithms execute on ordinary computers; quantum key distribution is a different hardware-based technology. [NIST explanation](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography).

| Protected property | Design |
|---|---|
| Session key establishment | Standards-based ML-KEM or supported hybrid protocol; verify actual negotiated group and peer interoperability |
| Authentication | Separately evaluate ML-DSA/SLH-DSA support, trust anchors and ecosystem compatibility; a PQ key exchange does not prove PQ authentication |
| Stored information | Standard authenticated encryption, protected key lifecycle and tested restore; do not invent cryptography |
| Updates | Signed metadata, expiry/rollback defenses, independent signing keys and platform-compatible package signing |
| Migration | Cryptographic inventory recording algorithm, provider, build, certificates, dependencies and negotiated outcome |

Use published standards and current errata: [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final), [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final), [SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final), [KEM integration](https://csrc.nist.gov/pubs/sp/800/227/final). Probe capability on the installed platform. Schedule tested adapter updates; never replace another application's cryptography by guessing its protocol. Cryptographic migration and exploit prevention remain separate control families.

Physics also informs resource governance: measure actual CPU time, memory residency, disk traffic, network use and energy where instrumentation supports it. Defer expensive analysis while the user is active; retain bounded security telemetry. Measure animation and model processes within the application's total budget.

## Intelligent adaptation without self-authorized changes

Run inference locally where practical. Treat retrieved content as data. The model can explain events, correlate supported evidence and propose policies; a deterministic gate validates every action. Stage learned rules in observation mode, test against held-out benign workloads, version them and retain rollback. Never train operational rules directly from unverified attacker-controlled labels.

Queue stability requires average processing capacity to exceed average arrival rate, but that alone does not handle bursts. Bound queues, reserve capacity for enforcement/verification and surface dropped-event counts. Under overload, reduce optional analysis and GUI work before essential recovery processing. A hidden queue backlog must not appear as a healthy machine.

## Three implementation-ready experiments

**A: Process network containment.** On owned test machines, use real benign client/server workloads and controlled authorized security tests. Observe traffic independently of the enforcement call, across supported routes and existing/new connections. Pass requires the intended restriction, no unrelated process restriction, accurate coverage reporting and recovery. Windows filter arbitration and other providers must be tested, not assumed. [Microsoft WFP arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration).

**B: Crash-safe recovery.** Interrupt execution at each transaction boundary; restart and compare actual policy with recorded intent. Add independent administrator edits. Pass requires correct reconciliation, no duplicate harmful mutation, and preservation of external changes. Authenticate IPC and use explicit pipe access rights; generic write can include pipe-instance creation rights. [Microsoft pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

**C: Cryptographic migration.** Inventory real components, negotiate with supported peers and record provider/group/authentication independently. Test downgrade policy, malformed inputs, rotation and recovery. Pass means the precisely stated exchange/authentication properties are observed; a library import or configuration flag does not count.

No probes, active attacks or experiments above were performed for this document.

## Delivery sequence and joint review

1. Agree supported Windows builds, protected user workflows, automatic action scope, evidence retention and comparison criteria.
2. Specify/model case B and authenticated helper ownership first; add protected installation/update handling.
3. Implement case A against that boundary, verify actual outcomes and reversible recovery.
4. Add evidence graph and calibrated decision engine; admit automation action by action.
5. Implement case C and interoperable crypto inventory/migration adapters.
6. Add optional scoped assessments, then independent comparative evaluation on real workloads.

Proposed module boundaries: evidence schema/store, policy authorization, operation journal, helper transport, enforcement adapters, outcome verification, graph planning, crypto inventory and evaluation reporting. These are design boundaries, not newly created application modules.

Before implementation, settle the highest-impact choices together: one-process containment versus wider isolation; which changes may run automatically; recovery behavior when external policy changes; supported OS builds; and acceptable measured disruption/resource budgets. The research dossier holds the broader primary-source register and challenged questions. This framework turns them into decisions, contracts and falsifiable experiments.
