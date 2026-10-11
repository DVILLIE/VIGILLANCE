# D'Vielle — Developer Onboarding and Engineering Handbook

Version 1.0 • 10 October 2026 • Proposed contributor procedure

## Start from project truth

Read the master index, charter, requirements, architecture, threat model and current repair records before editing. The inspected metadata targets Python >=3.12,<3.13. The repair checkout contains existing uncommitted work and approved visual changes; do not reset it or assume another checkout is equivalent.

Identify exact source state and installation/runtime separately. Existing test records establish only their recorded scope and revision. No historical pass is a substitute for verifying newly changed behavior.

## Workspace and authority

Use the authorized working checkout and preserve original project directories. Do not elevate a writable checkout, alter Windows policy or run active assessments during a documentation/review task. Application implementation follows the agreed plan; real security testing requires owned/authorized assets.

Respect explicit STOP immediately, preserve in-flight outcomes and avoid starting additional work.

## Source map

agent/privilege contains the closed operation contract and proposed transport boundary. agent/controller.py coordinates decisions. agent/evidence.py and agent/store/db.py are evidence/state integration candidates. agent/modules/firewall_apply.py and sandbox.py represent Windows control integration. agent/update/tuf.py handles update logic. dvielle/gui owns presentation and approved identity/motion work. Installer scripts have documented deployment holds.

Inspect implementation and tests before using any component; names alone are not proof of behavior.

## Implement a vertical capability

A capability change includes requirement, operation schema, authorization, target identity, precondition, intent journal, executor, independent postcondition, owned restoration, GUI result and tests. Do not implement a command first and add safety afterward.

Keep one policy authority. Reuse valid existing logic rather than creating a second uncoordinated executor. Type and validate external/model output before it reaches action planning.

## Verification workflow

Run relevant existing tests and meaningful regression cases for changed security behavior. Record actual command, environment, result and skipped checks. Broaden testing when changes/failures justify it. Unit fixtures are not real network/Windows evidence.

For integration, use controlled authorized machines and retain independent observations. Test error, concurrency, crash and external-change paths. A returned success string is not a valid enforcement oracle.

## Dependency and style discipline

Use exact reviewed release inputs and license notices; never fetch arbitrary mutable latest artifacts in an elevated path. Keep secrets outside source/logs/prompts. Preserve compatibility identifiers unless migration is part of the change.

Use clear names, explicit error states and bounded resource behavior. Human-facing copy uses D'Vielle. Do not change security ownership markers through broad spelling replacements.

## Review package

Provide the concrete problem, final behavior, relevant source changes, actual test evidence, risks and known gaps. Link requirement/threat/test IDs. A reviewer must assess the final implementation without needing chat history.

Update documents when authority, scope, schemas, compatibility or failure behavior changes. Do not claim functionality from documentation alone.

## Release participation

Before shipping, verify protected staging, artifact manifest, dependency notices, update root lifecycle, supported builds and recovery. A developer-run source checkout is not an installed protected artifact. Release authority remains with the human owner.
