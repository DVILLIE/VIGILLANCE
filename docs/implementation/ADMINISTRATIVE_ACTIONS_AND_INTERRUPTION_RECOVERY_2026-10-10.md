# D’Vielle Administrative Actions and Interrupted Upgrade Recovery

## Implemented changes

The Ethical Hacking workspace now includes Protection actions. The user selects an exact executable, Windows firewall profile, address families and remote networks. Windows elevation is followed by a separate review of executable SHA256 and the complete scope. Approval creates a single-use, five-minute permission; the bound normal-user client then submits it through the existing authenticated helper channel. Approval alone does not apply a rule. All instances of the executable are affected; launcher and child paths require separate scope.

Recovery accepts an exact recorded operation identifier, displays its recorded scope, and restores only matching owned rules after a separate confirmation. Unknown transport outcomes remain unknown. Cancellation prevents redemption of a late permission, but does not undo an already submitted operation. Receipts permit only Administrator/SYSTEM writes and bound-user reads. No authorization material is displayed in the GUI result.

The mediator validates closed requests, real Windows caller identity and process creation time, protected executable/module paths, and the installed runtime identity. It does not add arbitrary commands, grant issuance or recovery commands to the service pipe.

## Actual interrupted-upgrade acceptance

The reviewed experiment deliberately terminated the real upgrade worker with exit code 23 immediately after a harmless comment replacement. The durable journal and private predecessor backups survived. Explicit recovery conditionally restored only approved old/new bytes, restored the identity documents, verified all 5,790 predecessor files, restarted the exact owned helper, and restored the resident task. Before and after SHA256: 9a79ee47c21f81e6577b143df75f46f69f5f89d1f0332c82147399d0d77a69aa.

Evidence: ACTUAL_UPGRADE_INTERRUPTION_RESULT_2026-10-10.json. This is a real abrupt process exit, not a power-loss, disk-corruption, arbitrary interruption-point or complete rollback certification. No firewall mutation occurred in this experiment.

## Regression evidence

The full run recorded 690 passed and one readiness-thread timing failure at eight seconds. The failing check passed independently; the complete affected GUI and mediation contract subset then passed 22 tests. Preserve both logs. Contract tests do not establish operating-system enforcement or a human approval journey.

## Acceptance still required

The installed human approval/apply/recovery journey, accessibility, wider networking coverage, corruption and power-loss recovery, measured foreground and battery costs, optional AI isolation/evaluation, authenticated post-quantum migration, authenticated public update/uninstall and independent Windows pilots remain explicit release gates. A protected local deployment is not publisher authentication or public release certification.

Windows consent is preserved according to [Microsoft UAC documentation](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works). Service lifecycle follows [Microsoft service stop guidance](https://learn.microsoft.com/en-us/windows/win32/services/stopping-a-service).

## Installed deployment and independent verification

The protected increment completed with state activated_identity_verified and all 5,792 runtime files verified. Independent normal-user hashing matched SHA256 4f2ceb115cdc80af78ddfd20efcc76fd84f7717070785d113a456608ef052bbc. The actual installed widgets passed invalid-input checks with no elevation or firewall mutation. Human approval/apply/recovery is still not tested.

The readiness regression deadline was increased from eight to thirty seconds because it can inspect thousands of protected files and query SCM. The failing eight-second observation and successful targeted rechecks are retained; the bounded worker-completion assertion remains. Final regression results are recorded separately in MEDIATION_FINAL_REGRESSION_2026-10-10.txt.

## Final regression result

The complete final suite passed: **691 passed**, nine existing Pillow deprecation warnings, 96.27 seconds. No test failures remained in this final run. The original timing failure remains available in its separate historical log.
