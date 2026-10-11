# D'Vielle — AI Autonomy and Decision Engineering

Version 1.0 • 10 October 2026 • Proposed intelligent decision design

## Role of intelligence

AI correlates evidence, explains plausible hypotheses, prioritizes investigations and proposes actions. Deterministic policy and restricted execution own authority. The reasoner receives no general elevated shell, arbitrary file-write or unconstrained network-exploitation capability.

Start with fixed, explainable policies and real evidence before adding a model. A model is admitted only when it improves a held-out evaluation and respects the total resource/privacy budget.

## Decision model

Let H denote harm, E evidence and a a candidate action. Select the feasible action minimizing expected loss: sum_h P(h|E)L(a,h). Feasibility requires valid authorization, supported scope, fresh identity, available storage and a recovery plan. Loss includes attack damage, user interruption, containment failure and recovery cost.

Posterior odds follow prior odds multiplied by a likelihood ratio. Likelihoods and costs are not invented for this project. Calibrate them using real labeled observations and record methodology. Correlated signals require joint/dependent modeling rather than multiplying duplicate alerts.

Use a deterministic abstention route when evidence is missing or calibration does not apply. Abstention may mean collecting bounded additional evidence or asking for a consequential decision; it does not automatically suspend existing accepted protections.

## Evidence and output contract

A model proposal identifies evidence IDs, hypothesis, benign alternatives, proposed typed operation, target identity, expected outcome, uncertainty and explanation. Unknown or malformed output cannot become a command. Every cited event must exist and be within the authorized data scope.

Retrieved websites, filenames and documents are untrusted data. The model cannot redefine system instructions, policy, scope or update trust roots based on their contents.

## Learning and adaptation

Do not learn active enforcement directly from self-generated labels or attacker-controlled user content. Keep provenance-bearing feedback, distinguish observed outcomes from opinions and quarantine disputed labels. Version candidate rules/models and evaluate them in observation mode on separate real benign and security datasets.

Approve promotion only after comparing missed harms, false interventions, user disruption and resource cost. Retain prior versions, signed manifests and rollback. An adaptive detector may tune evidence interpretation; it cannot silently add privileged operations.

## Model supply chain and execution

Select models by exact version, source, license, weight hash, supported runtime and measured hardware behavior. Run optional inference in a restricted worker with bounded memory/CPU, data minimization and no default outbound connectivity. Verify the restriction rather than relying on an environment setting alone.

Model failures, excessive latency and overload leave the deterministic system usable. Surface dropped observations and degraded coverage. Tool output is checked against schema and scope before use.

## Evaluation

Evaluate explanations for evidence fidelity, hypotheses for calibration, and actions for policy compliance. Include indirect prompt injection, poisoned feedback, secret exfiltration requests, malformed outputs and unexpected tool invocation. These are future controlled tests, not fabricated results.

Use base-rate-aware precision and report confidence intervals with workload groups. A higher benchmark accuracy does not by itself demonstrate safer autonomous operation. Compare the whole intervention lifecycle.

[NIST adversarial ML](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) organizes poisoning, evasion and abuse risks. [OWASP excessive agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) supports narrow functionality and permissions. The exact policy, tests and acceptance evidence are D'Vielle engineering obligations, not assurances supplied by those publications.
