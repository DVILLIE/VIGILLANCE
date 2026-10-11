# D'Vielle — Audit Findings Repair and Acceptance

Date: 11 October 2026. Authoritative source: `E:\DVielleProjects\DVILLIE-main-repairs`.

This record supersedes older implementation checkpoints for the five findings in `E:\DVielleProjects\Audits\2026-10-11\DVielle_Implementation_Runtime_and_Migration_Audit.md`. Older reports remain historical evidence; this is not public-release certification.

## Findings and acceptance

| Finding | Repair | Verified result | Status |
|---|---|---|---|
| F1: Security log access denied | Explicit Windows approval added read access (mask 1) for the installed bound user to the existing Security channel DACL. Existing entries were preserved. | Normal-user Get-WinEvent read a real event. The installed production query completed without access error or degraded collection. No matching attack events occurred in the measured five-minute window. | Repaired on this computer |
| F2: idle process identified as CPU offender | Exclude PID 0 and System Idle Process before workload attribution. Preserve legitimate multicore process measurements. | Installed collection returned seven real process footprints, none representing idle capacity. | Repaired |
| F3: native access denial classified as invalid configuration | Recognize native Windows error 5 alongside PermissionError. | Installed normal-user readiness now reports `not_observed_access_denied`, with independent verification required; private ACLs remain protected. | Repaired |
| F4: stale implementation evidence | Select the latest successful activation by its completion timestamp and require an independent matching runtime digest and file count. Prefer the completed current full regression log and current readiness report. Write a dated manifest without overwriting the older checkpoint. | Current activation and independent inventory agree on 5,792 files and SHA-256 `143411b911539f26650d2882c0f8423e8780aacbf3476f8ea121660f7e1b925a`. | Repaired |
| F5: Windows camera and privacy gaps | Separate missing registry policy from access denial. Add bounded, read-only Windows camera privacy/history observations with explicit partial coverage. | Real camera metadata was readable, permission was Allow, and two history records were observed. These records do not prove current camera use or process ownership. | Privacy classification repaired; live camera ownership remains unverified |

## Runtime and regression acceptance

The protected increment changed six application Python files. Dependencies, grants, firewall rules, and private authorization material were preserved. The helper and resident task were restarted by the upgrade workflow. The completed protected receipt reports `activated_identity_verified`; a separate normal-user inventory independently matched the expected runtime.

`AUDIT_FIX_FINAL_REGRESSION_2026-10-11.txt`: **706 passed, 9 warnings**, 102.27 seconds. Warnings concern existing Pillow test-image APIs. Unit tests are regression evidence, not proof of an attack being stopped. No artificial attack or camera activity was generated for acceptance.

The read-only readiness probe still reports `activation_held` because it cannot inspect administrator-only configuration or establish every release acceptance gate. This does not contradict the separately authenticated update receipt and independent runtime inventory, and must not be relabeled as universal certification.

The restarted resident's real twin reports attacks and resource advisor `ok`, zero failures and no collection error. Privacy guard has a successful reading and no error; its deferred state is the scheduled interval between runs. AllowTelemetry is correctly reported as `not configured` and requiring review. Keep-on's remaining partial-coverage problem identifies camera live ownership only. This checkpoint is saved in `POST_AUDIT_FIX_RESIDENT_HEALTH_2026-10-11.json`.

## Security-channel permission scope and recovery

The read ACE applies to the bound Windows user, including other processes running as that user; it is not restricted to this application. It grants channel read access only. Audit policy was not changed and logs were not cleared. No full-system approval bypass was introduced.

Protected recovery record: `C:\ProgramData\DVielle\privileged\security-event-read-fedf152ad4794d8a8c2b250dbb89071b.json`. It contains original, requested and observed security descriptors. An administrator can restore the original descriptor only after confirming the current descriptor still matches the approved requested descriptor. If another administrator or policy changed it, compare and reconcile instead of blindly overwriting newer settings. Channel access can be revoked by policy; collection must then report unavailable again.

The first launcher attempts produced no completed receipt. After correcting snapshot construction, one increment completed successfully. A redundant subsequent preflight rejected the changed predecessor before mutation. Acceptance relies on the completed receipt and independent inventory, not process launch alone.

## Evidence files

- `SECURITY_EVENT_READ_SCOPE_RESULT_2026-10-11.json`: protected channel configuration receipt.
- `ACTUAL_SECURITY_EVENT_READ_2026-10-11.json`: actual normal-user Security event read.
- `PROTECTED_AUDIT_FIX_INCREMENT_PLAN_2026-10-11.json`: predecessor, six file hashes and expected successor.
- `PROTECTED_AUDIT_FIX_INCREMENT_RESULT_2026-10-11.json`: protected activation receipt.
- `EXPECTED_AUDIT_FIX_INCREMENT_RUNTIME_2026-10-11.json`: canonical expected inventory.
- `POST_AUDIT_FIX_ACTIVATION_RUNTIME_CHECKS_2026-10-11.json`: independent installed inventory comparison.
- `POST_AUDIT_FIX_READINESS_2026-10-11.json`: normal-user prerequisite observations.
- `ACTUAL_AUDIT_FIX_COLLECTOR_CHECKS_2026-10-11.json`: bounded real collector checks.
- `POST_AUDIT_FIX_RESIDENT_HEALTH_2026-10-11.json`: restarted resident observations.
- `IMPLEMENTATION_EVIDENCE_MANIFEST_2026-10-11.json`: current source/evidence ledger.

## Primary research and interpretation

Microsoft documents [event logging security](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging-security) and [channel security configuration](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/set-event-log-security-locally-or-via-group-policy). Permission repair uses the existing channel descriptor and a bounded read ACE rather than changing the account's administrative role.

Microsoft describes [camera privacy settings](https://learn.microsoft.com/en-us/windows/apps/develop/camera/camera-privacy-setting) and [Windows camera and microphone privacy](https://support.microsoft.com/en-us/windows/privacy/windows-camera-microphone-and-privacy). Permission/history metadata is not a live device-ownership API. This implementation reads existing metadata without opening a camera or storing frames and deliberately retains partial coverage.

Microsoft's [System policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system) and [diagnostic data configuration guidance](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization) distinguish supported policy floors, absent configuration and effective settings. Missing AllowTelemetry policy is a review item, not an access-denied error or proof of zero telemetry.

[psutil's API documentation](https://psutil.readthedocs.io/en/latest/#psutil.Process.cpu_percent) explains multicore per-process CPU percentages. Excluding idle accounting avoids blaming unused capacity without incorrectly clamping real workloads.

## Remaining work

Live Windows camera process ownership remains an explicit coverage gap. Product-wide prevention, all-application quantum-safe transport, universal packet containment and public-release certification are not established by these repairs. Older bounded firewall/TLS experiments remain scoped to their recorded targets and dates. The application must continue reporting incomplete measurements honestly.
