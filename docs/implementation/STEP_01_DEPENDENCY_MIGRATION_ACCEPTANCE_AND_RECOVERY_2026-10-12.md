# Step 01 — Installed dependency migration and recovery

## Outcome

This step is complete on the installed D'Vielle runtime. The four unused packages
**win10toast 0.9, pyttsx3 2.99, pypiwin32 223 and comtypes 1.4.17** are absent from
the active protected environment. Fifteen distributions remain, including the
thirteen retained dependency/build packages, pip and D'Vielle itself.
`python -I -B -m pip check` reports **No broken requirements found**.

The actual installed metadata now reports D'Vielle **2.5.0** and the native
notification/speech dependency declaration. The installed `pyproject.toml` matches
the reviewed source. The existing generated editable finder retains its internal
historical filename; its protected mapping still points to the installed application.
The active distribution directory and Version field are 2.5.0.

The protected runtime contains **5,445 files**, canonical SHA256
`5f2868ed1b79e08877f2b14be07140c96b5c752284cbc9af6a8daf9f92e1e78b`.
The worker receipt and independent fresh-process inventory agree. The helper is
running, and the resident task is running with Limited privileges. Firewall rules,
existing grants and private application data were not changed.

## Exact scope and preparation

The plan contains **370 file transitions**: retire 351 files owned by the four
packages and nine obsolete D'Vielle metadata files; create nine updated metadata
files; replace the project declaration. Shared distribution-file ownership was
checked before approving retirement. The comtypes-owned cache executable is
retired without running it. No other package namespace is admitted by the worker.

The existing environment was not moved or replaced. Python documents virtual
environments as generally non-portable. This migration instead preserves its exact
location, interpreter, launchers and retained dependencies. No pip uninstall hook,
package build or downloaded code was executed as Administrator.

The candidate archive SHA256 is
`5f9ce67e33040c5e8adfe4884aceae6eabe9fca465b4928b73202984def8c55d`.
Windows-approved staging created
`C:\Program Files\DVielleStage-aaf661e9ca3247d991e28bb341b7c7a1`.
The stage remains Administrator/SYSTEM-only. The immutable activation snapshot
checks the exact protected plan digest, file hashes, service binary/account,
resident command/account/RunLevel, pending recovery and predecessor runtime identity.

## Transaction and restoration

All predecessor bytes are backed up before maintenance begins. The helper and
resident are quiesced before active-file changes. Every change has a durable intent
written before mutation. Files are written through same-directory atomic staging;
only exact approved files are removed, and only empty owned directories are removed.
There is no recursive environment deletion.

Failures conditionally restore exact predecessor bytes, the old manifest and the
old identity receipt. Foreign edits and altered backups are refused. Unresolved
restoration holds the runtime instead of announcing success. A separate explicit
recovery entry accepts an exact interrupted journal; it never silently restarts an
arbitrary service or restores arbitrary paths.

The retained protected backup is
`C:\ProgramData\DVielle\privileged\dependency-upgrade-4d477a2cf4fa4625840dcf9fc304d090`.
The readable successful receipt is
`C:\Program Files\DVielle\dependency-result-dependency-upgrade-4d477a2cf4fa4625840dcf9fc304d090.json`.
Backups are retained for evidence and conditional recovery. They are outside the
active import environment and are not included in a public upload.

## Actual acceptance evidence

| Check | Observed result |
| --- | --- |
| Local full regression | 727 passed, nine existing Pillow deprecation warnings, 63.93 seconds. |
| Real copied installed files | All 370 transitions applied and exact original bytes restored on a disposable copy. |
| Controlled process interruption | Child actually exited with code 23 after four file mutations and five durable intents; exact predecessor restored. |
| Standard Windows token | Actual non-elevated execution refused installed migration before mutations. |
| Protected worker | Exit code 0; `dependency_migration_identity_verified`. |
| Independent installed inventory | Exact expected successor digest and 5,445 files. |
| Installed dependency check | No broken requirements; all four retired distributions absent. |
| Installed editable RECORD | All 13 hashed file entries match their actual bytes and sizes; no missing unhashed entry. |
| Installed notification and speech | Both native calls returned successfully after package removal. Human visibility/audio is not asserted. |
| Installed GUI | Keyboard/scaling driver loaded `C:\Program Files\DVielle\dvielle\gui\assessment.py` and passed; no callback errors or security mutations. |
| Installed metadata notices | 47 retained notice files across all 15 active distributions; no package missing a notice in the inspected metadata paths. |

The controlled interruption occurred on disposable copies, not on the user's
working installation. It establishes the file-recovery mechanism; it is not a
power-loss test or an interrupted live Windows service deployment.

The first GUI invocation used the development interpreter. Its source observations
are preserved separately. The driver now refuses `--installed-runtime` unless the
loaded module is the protected installed module. The corrected installed run passes.

Evidence files include `ACTUAL_INSTALLED_DEPENDENCY_MIGRATION_2026-10-12.json`,
`PROTECTED_DEPENDENCY_MIGRATION_RESULT_2026-10-12.json`,
`ACTUAL_DEPENDENCY_COPY_RECOVERY_FINAL_2026-10-12.json`,
`ACTUAL_DEPENDENCY_MIGRATION_INSTALLED_GUI_2026-10-12.json` and the installed SPDX
inventory. Current retained notices are under
`docs/legal/installed-third-party-2026-10-12/inventory.json`.
Notice presence is an inventory result, not legal clearance of every native/OS
dependency or a public installer certification.

## Explicit interrupted recovery procedure

1. Preserve the exact stage, approved archive, plan, journal and predecessor backup.
2. With an approved Administrator token, identify the exact interrupted
   `dependency-upgrade-<32 hex characters>` journal. Verify its plan matches the
   approved plan and its state is prepared, applying, failed or manual recovery required.
3. Confirm the owned helper is stopped and the owned Limited resident task is
   disabled and stopped. The recovery worker refuses a running or foreign runtime.
4. Run the reviewed local immutable launcher with
   `--recover dependency-upgrade-<exact identifier>`. Its Windows UAC boundary and
   protected stage checks remain in force. Inspect the protected diagnostic and
   readable result receipt; an exit code alone is insufficient.
5. Independently verify predecessor inventory, dependency consistency and the
   owned helper/resident state. Preserve failure evidence if any check disagrees.

The successful journal for this completed migration is not an interrupted journal
and is deliberately rejected by that recovery route. An intentional later downgrade
requires a separate reviewed plan; it is not disguised as crash recovery.

## Next step

The next separate step is **protected public installer/bootstrap integration**.
No setup-wrapper hold was removed, no public installer was built and no release or
merge was performed as part of this dependency migration.

The four reviewed source/test files were pushed to the existing
[draft PR 26](https://github.com/DVILLIE/VIGILLANCE/pull/26), commit
`c89937aa76d394d8e4bc996dca88836d4facf770`.
Machine reports, private backups and signing material were not uploaded.
The independent Windows validation for this commit is
[run 38168890152](https://github.com/DVILLIE/VIGILLANCE/actions/runs/38168890152);
its result must be read separately from earlier successful runs.

That run completed successfully. Both hosted Windows regressions recorded
**701 passed, 26 explicit skips and zero failures/errors** out of 727 collected
tests. The additional skipped contract requires a real standard Windows token;
it passed in the separate local standard-token suite. Both real GUI reports passed.
All four XML/GUI attestations were independently verified against the repository,
workflow, pull-request ref and exact run invocation. Evidence is retained in
`ACTUAL_REMOTE_DEPENDENCY_ACCEPTANCE_2026-10-12.json` and the corresponding four
`DEPENDENCY_REMOTE_ATTESTATION_*` files. Browser/general CI also passed. The setup
workflow remains a held/skipped build, so its green status is not an installer.

## Primary references

- [Python virtual-environment portability](https://docs.python.org/3.14/library/venv.html).
- [pip uninstall behavior](https://pip.pypa.io/en/stable/cli/pip_uninstall/).
- [pip dependency consistency checks](https://pip.pypa.io/en/stable/cli/pip_check/).
