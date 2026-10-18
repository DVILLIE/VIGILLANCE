# D'Vielle Current Acceptance and Implementation Plan — 12 October 2026

## Current verified installation

After completed dependency migration, the installed protected runtime contains
**5,445 files**, canonical SHA256
`5f2868ed1b79e08877f2b14be07140c96b5c752284cbc9af6a8daf9f92e1e78b`.
Protected activation and independent inventory agree. The privileged helper and
the Limited resident task are running. Actual installed notification and native
SAPI calls returned successfully; human visibility/audio confirmation is not asserted.

The latest local full regression passed **727 tests**, with nine existing Pillow
deprecation warnings, in 63.93 seconds. Source fixes replace legacy notification
and speech dependencies, correct hexadecimal voice language selection, treat spoken
observations as plain text, and bound both notification and speech queues.
The thirteen-wheel future-install candidate was verified against official PyPI
artifact records and resolved offline with exact hashes. The four unused legacy
packages were then retired through an explicit backed-up migration. They are absent
from the active environment; 15 distributions remain and `pip check` passes.
Installed package metadata and the project declaration now agree on version 2.5.0.

Full change and acceptance evidence:
[Native notification and speech integration](NATIVE_NOTIFICATION_AND_SPEECH_INTEGRATION_2026-10-12.md).
The completed first step is documented in
[Dependency migration acceptance and recovery](STEP_01_DEPENDENCY_MIGRATION_ACCEPTANCE_AND_RECOVERY_2026-10-12.md).
The current evidence manifest is `IMPLEMENTATION_EVIDENCE_MANIFEST_2026-10-12.json`.

## Remaining acceptance areas

All eight areas still have remaining acceptance work. Previously completed checks
and exact open conditions are retained in the
[11 October detailed ledger](CURRENT_ACCEPTANCE_AND_IMPLEMENTATION_PLAN_2026-10-11.md#eight-acceptance-areas).
Its installed identity and test total are historical; the current values are above.

| Area | Remaining work |
| --- | --- |
| Network enforcement | Real IPv6, QUIC, VPN/proxy, child-image and conflicting-policy checks, with independent outcomes and restored baselines. |
| Upgrade/recovery | Additional interrupted/corrupted and multi-version upgrade checkpoints on isolated supported targets. |
| Accessibility | Narrator, contrast/flash review, consequential-action cancellation, and clipped high-scaling tab headers. |
| Performance/privacy | Randomized wider workloads, battery behavior and independent all-process network observation. |
| Attack-path automation | Representative authorized attack outcomes, measured error rates and accepted rollback for consequential automation. |
| Optional AI | Outbound-denying isolated model execution and held-out fidelity/benefit evaluation; local memory admission remains failed. |
| Post-quantum trust | Authenticated public publisher/update roots and PQ network identity, separate from local report signatures. |
| Public distribution | Verified protected installer/compiler bootstrap, actual setup/install/upgrade/uninstall/rollback acceptance and supported Windows client pilots. Current installed metadata notice reconciliation is recorded: 47 notice files for 15 active distributions; native/OS completeness and final shipped-artifact review remain separate. |

## Immediate integration sequence

1. Independent hosted regression, GUI acceptance and four result-attestation
   verifications completed successfully for the native integrations.
2. **Completed:** clean thirteen-wheel installation validation and the protected
   installed dependency migration, with exact backups, file-copy interruption
   recovery, independent installed inventory, `pip check`, actual installed native
   calls and installed GUI checks. Historical notice evidence is retained separately.
3. Implement and validate protected installer/bootstrap staging. Keep the public
   setup hold until that path actually passes installation and recovery acceptance.
4. Continue the remaining isolated enforcement/recovery checks and optional AI
   isolation/evaluation. Never count a candidate artifact or recommendation as
   real execution acceptance.

No public release or merge has occurred. The existing PR remains a draft.

Independent [hosted run 38166949351](https://github.com/DVILLIE/VIGILLANCE/actions/runs/38166949351)
completed successfully: both Windows Server runners recorded **694 passed and 25
explicit skips**, zero failures/errors, and real GUI keyboard/scaling acceptance.
All four XML/GUI attestations were independently verified and bound to this exact
run invocation. Browser/general CI also passed. The installer workflow's green
status still represents a held/skipped build, not a setup executable.

The later dependency migration source is independently verified by
[run 38168890152](https://github.com/DVILLIE/VIGILLANCE/actions/runs/38168890152):
both Windows regressions recorded **701 passed and 26 explicit skips**, zero
failures/errors, real GUI acceptance and four independently verified result
attestations bound to that exact invocation. The local standard-token suite passed
all 727 tests, including the additional non-elevated migration refusal contract.
