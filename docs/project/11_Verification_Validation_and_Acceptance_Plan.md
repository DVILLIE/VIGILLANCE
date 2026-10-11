# D'Vielle — Verification, Validation and Acceptance Plan

Version 1.0 • 10 October 2026 • Proposed quality plan

## Evidence levels and test environment

Keep documentation review, static source review, unit results, model checking, Windows integration, real workload evaluation and field evidence separate. Each result names source/artifact revision, OS build, hardware, configuration, tools, inputs, timestamps, expected outcome and observed outcome. Controlled tests will use owned/authorized assets; none has been run to produce this document.

Unit fixtures and state models may verify narrow implementation properties, but cannot substitute for real enforcement or user-workload evidence. Do not report generated or modeled events as actual attacks prevented.

## Test organization

| ID | Test class | Acceptance obligation |
|---|---|---|
| VT-01 | Evidence identity/freshness | Actionable records retain identity/provenance; missing facts remain unknown |
| VT-02 | IPC authority | Unauthorized, replayed, malformed and unsupported requests cause no mutation |
| VT-03 | Target race | Replaced files/PID reuse/stale authorization fail safely |
| VT-04 | Crash/recovery | Every transaction boundary reconciles without duplicate mutation |
| VT-05 | External changes | Recovery preserves unrelated administrator/user edits |
| VT-06 | Network effect | Claimed restriction is observed independently across supported paths |
| VT-07 | Coverage loss | Missing sensor/service/feed produces correct degraded status |
| VT-08 | Updates/install | Substituted, stale or writable elevated inputs are refused |
| VT-09 | Assessment scope | Redirect, DNS and cancellation cases remain in scope |
| VT-10 | Privacy | Real storage/egress/export match purpose and sharing settings |
| VT-11 | AI boundary | Hostile inputs cannot expand authority or leak protected data |
| VT-12 | Crypto | Actual exchange/authentication/rotation meet stated policy |
| VT-13 | Performance | Total overhead and benign task latency meet agreed budgets |
| VT-14 | Accessibility | Essential journeys work with keyboard/Narrator/reduced motion |
| VT-15 | Offline/failure | Core observation/recovery remain truthful and usable |

## Combinatorial design

Use the network factor matrix in the earlier design framework: address family, existing/new connection, TCP/UDP/QUIC workload, route, process relationship, interfering policy, crash point and caller class. Its unconstrained product is 3,888 configurations. Declare feasibility constraints and generate covering arrays rather than claiming all combinations were executed.

Start with 3-way interaction coverage; increase strength for critical coupled factors and add mandatory adversarial/race cases irrespective of coverage. Measure achieved interaction coverage. Test event ordering separately. [NIST ACTS](https://csrc.nist.gov/Projects/Automated-Combinatorial-Testing-for-Software) provides free public-domain tools; obtaining a download currently requires a request, which has not been sent.

## Statistical protocol

Predeclare datasets, labels, exclusions, independent unit and stopping rule. Separate tuning and evaluation. Report prevention/miss rates, false interventions and latency distributions with denominators and confidence intervals. Keep workload/device clusters separate where observations are correlated.

With zero failures in independent representative Bernoulli trials, a one-sided 95% upper bound is 1 - 0.05^(1/n). Required zero-failure counts are 299 for 1%, 2,995 for 0.1% and 29,956 for 0.01%. These are planning calculations, not results. No inference about all attacks follows from one finite test population. [NIST exact binomial guidance](https://itl.nist.gov/div898/software/dataplot/refman2/auxillar/exacbino.htm).

## Benign and comparison workloads

Use real browsing, video calls, office work, downloads, development tools, VPN use, sleep/resume and update activity. Record task completion/disruption. Compare with the same free Windows protection baseline on comparable machines/configurations. Isolate machine differences and retain adverse outcomes rather than selecting favorable runs.

Set numerical latency/resource/disruption thresholds after pilot measurement but before held-out evaluation. Changing them afterward requires a new evaluation baseline.

## Release decision

Block a feature on unauthorized mutation, unreconciled state, unsafe restoration, secret disclosure or falsely verified protection. A failed advanced adapter may be excluded while a narrower truthful release proceeds. Document scope, unresolved defects and supported environments. Passing process checks is not itself proof of efficacy.
