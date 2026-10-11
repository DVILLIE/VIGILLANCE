# D'Vielle — Python 3.14 Protected Deployment and Launcher Repair

Date: 10 October 2026. Scope: this Windows computer; local operator-approved installation. This report does not certify a public release or universal attack protection.

## Implemented and observed

The runtime launcher now executes `exit 0` after its successful installer checks and resource cleanup, so the Explorer PowerShell invocation finishes instead of leaving an idle successful launcher. Failures still propagate. An already open console from an earlier invocation does not reload the changed script.

The actual installed Python executable reports 3.14.8. Protected ownership, writer and ancestor checks passed for its path. Seventeen pinned runtime dependencies installed offline into a separate 3.14 validation environment. `pip check` found no broken requirements, all 24 smoke checks passed, and the first complete 3.14 regression run passed 658 tests with nine Pillow deprecation warnings in 106.61 seconds. These results are actual executions; unit fixtures are not evidence of attacks or packet containment.

Protected staging initially failed because PowerShell treated SID strings as account names in `FileSystemAccessRule`. The launcher now constructs `SecurityIdentifier` objects. Elevated failure diagnostics use exclusive file creation with Administrator/SYSTEM write access and the invoking user's read access. Staging subsequently succeeded. Sixteen PowerShell installer contract checks passed after this change.

Candidate r5 SHA256: `811b9b7b34fba1788b21ffc5cb4fd1bc203c1d6b68ab74cad28569d5f95a3cd1`. Protected stage: `C:\Program Files\DVielleStage-e3df45f8e3514857a485f3e61a97fd20`. This is a local candidate, not a publisher-signed public release.

Installation encountered the previous `DVielle` and `DVielleGUI` tasks pointing to `C:\DVILLIE-main`. Their exact executable, arguments and working directory were verified and their XML exported before disabling/removing them. Original project directories were preserved. Installation then succeeded under `C:\Program Files\DVielle`, with offline dependencies, smoke checks, permission checks, branding and startup verification. The new resident task runs at Limited privilege and a current heartbeat/process identity was verified. Installer-requested failure audit settings were applied; the installation log records readback.

Protected private helper state and the exact Windows user binding were created. Helper registration exposed an inconsistent ancestor check: the Python checker rejected metadata writes on Windows' standard `ProgramData` ancestor while the PowerShell installer checked replacement/deletion authority. The Python ancestor mask now matches that replacement threat: DELETE, FILE_DELETE_CHILD, WRITE_DAC and WRITE_OWNER are rejected for untrusted principals. Target objects continue to reject all mutation rights. No system folder permissions were weakened. Forty related ACL, identity and grant tests passed.

The approved checker patch was held under a read-only file lease, independently hash-checked, copied into protected storage, and atomically replaced only after checking the installed predecessor digest. The old installed checker was backed up. A new actual runtime inventory contains 5,786 files and was independently verified against SHA256 `05ba03cd7ec64a1c9939b5660ae89e9966f07271646dd762bb96288f4c1f1528`. The earlier inventory and r5 archive are historical predecessors to this single-file patch.

The helper was registered stopped, with protected service permissions and this exact approved runtime. Starting, live peer authentication and enforcement results must be recorded separately below; registration alone establishes none of them.

## Evidence and recovery

- `PYTHON314_TEST_RESULTS_2026-10-10.txt`: first full 3.14 suite.
- `PYTHON314_SMOKE_RESULTS_2026-10-10.txt`: smoke and dependency checks.
- `LAUNCHER_STAGING_TEST_RESULTS_2026-10-10.txt`: 16 installer checks.
- `ANCESTOR_ACL_TEST_RESULTS_2026-10-10.txt`: 40 targeted checks.
- `PROTECTED_INSTALLATION_RESULTS_2026-10-10.txt`: actual installation log snapshot; later helper activity appears in the continuing protected log.
- `PREVIOUS_RESIDENT_TASK_2026-10-10.xml` and `PREVIOUS_GUI_TASK_2026-10-10.xml`: previous startup definitions, retained for reviewed recovery.
- `C:\Windows\Temp\DVielle-migration-20261010-e3df45f8.log`: continuing Administrator-owned log.

Restoring an old task or updating a registered helper must include identity, permissions, pending-operation and recovery review. Do not run the old mutable checkout as SYSTEM or delete protected recovery records. No firewall mutation was performed during installation or registration.

## Primary references

- [Microsoft PowerShell script execution](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_scripts): script and exit behavior.
- [Python 3.14 virtual environments](https://docs.python.org/3.14/library/venv.html): separate runtime validation environments.
- [Microsoft file security and access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights): file, directory and parent access semantics.

## Remaining acceptance

### Actual live helper acceptance

The first live client check failed with Windows error 5 when querying the SYSTEM process. The host now grants only PROCESS_QUERY_LIMITED_INFORMATION on its process and TOKEN_QUERY on its token to the exact configured Windows user. SYSTEM identity and a resolved user account are required before this permission is published. Process/token modification permissions are not granted.

The exact stopped helper was verified and removed for this reviewed upgrade; protected identity records and source predecessors were preserved as backups. The revised 5,787-file runtime was independently verified against SHA256 `b9f5eec45d6849fb500c1eb27fea2866138427cfe9531de5ecf46a8b9d261469`, registered and started. The live helper is running, and a normal-session client authenticated its actual SYSTEM token, protected image and SCM process identity before sending a request.

An actual request using a nonexistent grant returned `unauthorized`, `performed: false`, and `state_unknown: false`. No authorized firewall request was issued. Separate actual normal-session checks succeeded for identity queries and received access-denied errors for process termination, memory writes, thread creation, DACL modification, token duplication, privilege adjustment and token DACL modification. Results are saved in `LIVE_HELPER_UNAUTHORIZED_REQUEST_2026-10-10.json` and `LIVE_HELPER_QUERY_PERMISSION_RESULTS_2026-10-10.json`.

Normal-session readiness cannot read Administrator/SYSTEM-private configuration; this is an intentional private-data boundary, not evidence that the configuration is absent. The direct privileged configuration observation and actual mutual-authentication results above are distinct from that normal-session report.

Sources: [Microsoft process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) and [OpenProcessToken access requirements](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken).

### Actual scoped apply and recovery

An administrative one-use grant authorized only this installation's `python.exe`, all firewall profiles, IPv4 and the documentation destination `192.0.2.1/32`. The normal-session native client applied operation `7963a5b31c704fa4855cc64a726fd755`; Windows configuration readback verified the exact outbound block rule and ownership marker. This was an actual policy mutation, not packet-containment evidence.

Recovery first refused deletion because the unconfigured package filter was empty instead of the expected literal `Any`. The corrected guard requires the package property to exist and accepts only empty or `Any`; actual package restrictions remain a conflict. Remote comparison now canonicalizes host/CIDR and IPv6 spelling, masks network host bits and rejects unrecognized values instead of comparing raw formatting. In a read-only diagnosis all conditions then matched the actual rule. The reviewed conditional removal deleted only the exact invocation-owned rule. Administrative reconciliation returned `restored`, and a separate PersistentStore lookup confirmed the test rule is absent.

The installed recovery module was updated through a pinned, leased patch and predecessor check, with old source and identity records backed up. The expected inventory was independently derived from the previously verified inventory and the exact patch/backup bytes. Actual registration verified all 5,788 files against SHA256 `d0d7d6d7df70beb668fd7e93bd3c5b8f6ee467a9884de31f552e8f08850c3811`; the corrected helper is running. The latest native request again returned `unauthorized` without effects. No test rule remains.

Final Python 3.14 regression: **660 passed, nine existing Pillow warnings, 88.61 seconds**. Source whitespace checks passed for the changed implementation files. Updated local candidate r6 contains 269 files, SHA256 `f27c826103a07e1895dcaf8961ddb2bc6a470bd9422eeedd6f12aceea4400cf7`; it is unsigned and has not been installed as a whole archive. The installed candidate plus the reviewed protected patches are identified by the runtime baseline above.

Real PowerShell address-normalization checks cover equivalent IPv4 and IPv6 host forms, network masking, distinct hosts and refusal of unknown scope. These pure comparison tests do not change firewall rules. The full final regression result is saved separately in `PYTHON314_FINAL_TEST_RESULTS_2026-10-10.txt`.

Scoped packet enforcement and conditional restoration, crash/recovery trials, measured performance/accessibility and broader Windows coverage require their own actual evidence. Public publisher signing, authenticated release/update roots, key rotation and independent pilot acceptance remain separate from local operator digest approval. The full twenty-step project plan is not marked complete by this installation.
