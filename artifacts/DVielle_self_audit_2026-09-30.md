# DVielle co-owner self-audit — 2026-09-30

**Tree reviewed:** `main` @ `4dd62e072dd5cebf6ada64c3d5ac018394d2f2ab` (2.3.1, “verify_runtime pythoncore venv shim”).  
**This note also records one fail-closed gate fix made from that finding** (Sensitive auto-protect severity is enforced inside the mutate gate).  
**Live Windows resident results:** UNCHECKED. Another agent owns the laptop. Nothing below is a field proof.

Sources checked while judging claims (fetched 2026-09-30):

- TUF specification 1.0.36, detailed client workflow, https://theupdateframework.github.io/specification/v1.0.36/ — intermediate root expiry is not checked until step 5.3.10, and the client persists each new root before that freeze check.
- Microsoft Learn, Windows Sandbox, https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/ — Yes on Pro, Enterprise, Pro Education/SE, and Education. Home is not supported.
- Microsoft Learn, Windows security edition requirements, https://learn.microsoft.com/en-us/windows/security/licensing-and-edition-requirements — App Control for Business and Windows Sandbox are listed for Pro. The Enterprise column note says it applies to IoT Enterprise for features that are not marked otherwise.
- Microsoft Learn, Windows Sandbox CSP, https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowssandbox — IoT Enterprise / IoT Enterprise LTSC is in the edition list for those settings.
- Intune App Control for Business, https://learn.microsoft.com/en-us/mem/intune/protect/endpoint-security-app-control-policy — Windows 11 SE policies in education tenants are deployed automatically and cannot be changed.
- W3C WebAuthn Level 3, https://www.w3.org/TR/webauthn-3/ — credential scope is the relying party. Already reflected in `agent/modules/passkeys.py`.

Local checks on this cloud Linux host (Python 3.12.3, process name `python3`), after the gate fix: `python3 -m pytest -q` → **407 passed, 13 skipped, 0 failed**. `python3 scripts/smoke_test.py` passed. Selected ruff (`E9,F63,F7,F82`) passed. The 13 skips are the existing Windows-only cases. This run is not `verify_runtime` on a resident, and it is not an elevated ACL field prove.

---

## Executive co-owner summary

1. 2.3.1 on `4dd62e0` still matches the product locks that matter: no install-time `ExclusionPath`, resident task default RunLevel Limited, dual mutate gate fail-closed on an unsaved decision, CFA copy is a modification shield, passkeys stay RP-scoped with `phishing_impossible: false`, privileged auto-update stays off, and the helper that actually listens is still the loopback stub.
2. The claims page, trust gates, and function spec are unusually honest about leftovers. Do not “finish” those leftovers by turning on Highest unattended, a SYSTEM helper, a phishing-impossible badge, or a Defender exclusion.
3. One real gate hole was open: Sensitive’s critical auto-protect floor lived only in `ResolutionEngine._try_auto`. `PolicyGate.issue` and `DualGate.perform` called `experience_allows_auto` without severity, so a high-severity auto token for `storage.free_safe_temp` could delete temp files. That path is now fail-closed.
4. GitHub Actions on this exact main commit is red. Run `36599565020` (2026-09-29): `browser` passed, `test` failed one case, `test_valid_partial_collection_keeps_catchup_cadence_and_reports_gap`. `docs/TRUST_GATES.md` still describes the earlier green 2.3.0 Windows run.
5. `docs/TUF_POUF.md` said KEV and OSV were “later work” after 2.2.0 shipped local loaders. That sentence is corrected in this change. abuse.ch dumps are still not bundled.
6. Everyday’s experience contract does not add ASR/CFA/firewall proposals, but `security.promotion.options` is still published on the twin for every experience. The sentence “Everyday does not propose those mutations” is tighter than the snapshot.
7. `EditionID` values `cloudedition` and `iotenterprise` are classified `ProOrHigher`, which marks Windows Sandbox AVAILABLE. IoT Enterprise is supported by the Sandbox CSP page. Windows 11 SE (`CloudEdition`) is not on the Sandbox Yes table. That cell is not field-proved.
8. Live `verify_runtime`, the elevated ACL field prove, the named-pipe SYSTEM helper, privileged auto-update, engine freshness, and live binary attestation stay UNCHECKED. Leave them marked that way.
9. Optional hosts hardening does not list MAPS hosts in the default domain file, and the resident does not apply that script. The update-safe allow-list still does not name `wdcp.microsoft.com` or SmartScreen, so a later domain-list edit could block Defender cloud. Not a default.
10. Do not treat this Linux unit run, or the red Windows CI run, as a laptop field pass.

---

## Ranked findings

### HIGH — Windows CI on 2.3.1 main is red

**Evidence.** https://github.com/DVILLIE/VIGILLANCE/actions/runs/36599565020 for `4dd62e0`. Job `test` failed. Job `browser` succeeded. The only pytest failure:

`tests/test_autonomous_runtime.py:111` `test_valid_partial_collection_keeps_catchup_cadence_and_reports_gap`

```text
assert plane.due(spec.last_run_monotonic + 30) == [spec]
AssertionError: assert [] == [CollectorSpec(... status='partial' ...)]
```

`agent/nerve.py` resets failures to 0 on `CollectionIncomplete` and stamps `last_run_monotonic` in `finally`. `due()` treats the collector as due when `now - last_run >= interval`. The test asks for exactly `last + 30`.

**Impact.** `main` does not have a green `ci / test` at the commit operators are asked to install. Trust-gate prose still points at the 2.3.0 green run (`36591371092` / the 2.3.0 push `36592020697`). A partial attacks collector that is not due again at its interval would stall catch-up; this single Windows failure does not by itself prove that stall, because the same test passed in the Linux run above.

**Next action.** fix-now on a Windows runner: print `now`, `last_run_monotonic`, and `_interval` in that assertion. If the delta is a hair under 30, loosen the fixture. If `due()` is genuinely empty for a larger reason, fix the scheduler. Do not paint the trust-gate box green until that run is green.

### HIGH — Sensitive auto-protect floor was not inside the mutate gate

**Evidence (before this change).** `agent/experiences.py` `experience_allows_auto` applies `auto_protect_min_severity` only when `severity` is passed. `agent/engine/loop.py` `_try_auto` passed it. `agent/engine/policy.py` `PolicyGate.issue` and `agent/policy/dual.py` `DualGate.perform` did not. Sensitive sets that floor to `critical` (`agent/experiences.py` resolve path). `storage.free_safe_temp` is in `PUBLISHED_AUTO` and maps to `DELETE_TEMP`, which is not in `USER_APPROVED_ONLY`.

**Impact.** The evaluate path was safe. Any caller of `policy.issue(..., auto=True)` for temp cleanup, then `handlers.invoke`, could auto-delete temp files on a high (not critical) finding while Sensitive was active. That contradicts `docs/CLAIMS.md` pillar 8 and `docs/FUNCTION_SPEC.md` §40 item 85.

**Next action.** fix-now. Done in this change: both gates pass severity, and a missing severity is below every published floor. `tests/test_worldclass_p5.py` `test_sensitive_gate_refuses_auto_temp_delete_below_critical` covers the refusal and a critical token still issuing. `safety.turn_protection_on` is still a no-op (`agent/engine/handlers.py`); it is not in `HANDLER_KIND`, so it never reaches `DualGate`.

### MEDIUM — “Everyday does not propose” is true of the experience object and false of the prevention snapshot

**Evidence.** `agent/experiences.py` `_proposals` returns `[]` unless the name is Sensitive, and those rows are `applied: false`. `agent/modules/security.py` always `build_promotion(...)`. `agent/runtime.py` publishes both `experience` and `promotion` on the twin. `agent/engine/observations.py` `from_security` does not turn promotion rows into tickets. Applying them still needs a user-approved dual-gate call.

**Impact.** A console or later caller that renders `promotion.options` will show ASR/CFA next steps during Everyday. The spec sentence in `docs/FUNCTION_SPEC.md` shipped-honesty 2.3.0 (“does not propose those mutations”) over-reads the snapshot.

**Next action.** discuss. Either stop publishing promotion options while Everyday is active, or narrow the claim to “the experience contract adds no proposals; the prevention report still lists eligible next steps, unapplied.” Do not delete the dual-gated ASR/CFA path.

### MEDIUM — `CloudEdition` inherits a Pro sandbox / App Control cell

**Evidence.** `agent/edition_matrix.py` `classify_sku`: `edition_id` starting with `cloudedition` or `iotenterprise` returns `ProOrHigher`. `_features` then sets `windows_sandbox` and `app_control_authoring` to AVAILABLE. Home is forced back to UNAVAILABLE. Tests lock Home, not CloudEdition.

**Impact.** IoT Enterprise sandbox support is consistent with the Sandbox CSP page reviewed 2026-09-30. Windows 11 SE (`CloudEdition`) is absent from the Sandbox Yes table, and Intune documents its App Control policies as automatic and not editable. A SE machine can be shown Sandbox AVAILABLE and App Control authoring AVAILABLE without a probe.

**Next action.** field-prove the live `EditionID` / caption on a Home PC and, if one exists, a Windows 11 SE PC. Until that reading exists, treat `cloudedition` sandbox and authoring as UNKNOWN, not AVAILABLE. Do not mark Home sandbox available to “simplify” the matrix.

### MEDIUM — Docs that still describe an older tree

**Evidence.**

- `docs/TUF_POUF.md` said the POUF “does not ship CISA KEV, OSV, or abuse.ch. Those feeds are later work.” Local KEV/OSV loaders shipped in 2.2.0 (`agent/intel/`). Corrected here to say the wire format does not bundle feeds, KEV/OSV are separate, and abuse.ch dumps stay out.
- `docs/VIGILLANCE_MASTER_ARCHITECTURE.md` repository map still lists `installer/install-dvielle.ps1` Defender `ExclusionPath` as **REMOVE**, and lists “Attack surface … ASR audit” and “Software inventory + CVE mapping” as explicit GAPs. Installer ExclusionPath is already absent (`tests/test_install_acl_contract.py`). ASR observation and local KEV/OSV exist. The map has no CURRENT/HISTORICAL label on those rows, which breaks the doc’s own review rule.
- `docs/LAPTOP_ONLY.md` and `docs/TELEMETRY_AND_HOME.md` headers still say “Updated 2026-09-13 for DVielle 1.6.0.” The install page body does describe the 2.3.1 venv re-sync. The header does not.
- `docs/TRUST_GATES.md` opens with “Version 2.3.0 ships P5.” The 2.3.1 verify_runtime note is only in the unchecked P5 box. The green pytest narrative is the 2.3.0 Linux run (392 passed, 13 skipped, 1 failed) plus a Windows success that is not run `36599565020`.
- `README.md` lead sentence still anchors on “Version 2.0.0 keeps the 1.7.0 dual gate” and then narrates forward. `pyproject.toml` version is 2.3.1.
- `docs/FUNCTION_SPEC.md` sections titled “Shipped honesty (1.8.0)” and “(1.9.0)” still say TUF is not built. Later sections correct that. A reader who stops early will mis-brief.

**Impact.** An auditor or installer can brief the wrong generation. None of these sentences re-introduce ExclusionPath by themselves.

**Next action.** fix-now for the master-architecture status labels and the 1.6.0 page headers, after this gate fix. Do not rewrite the historical function-spec sections without keeping the version labels.

### MEDIUM — Privileged helper trust boundary is the TCP stub, not the pipe ACL

**Evidence.** `agent/privilege/pipe.py` builds an SDDL for SYSTEM plus one user SID and refuses Everyone. The comment says a `CreateNamedPipe` server is a skeleton and is not started by the Limited task. `agent/privilege/helper.py` `LoopbackHelper` binds `127.0.0.1`, writes `helper_endpoint.json` including the bearer token (`write_endpoint`), and dispatches `restrict_network`. `agent/privilege/contract.py` checks the path and the address families. It does not apply `SYSTEM_PROTECTED`. `agent/engine/handlers.py` `restrict_network` does refuse those names before the call. `agent/modules/firewall_apply.py` will `New-NetFirewallRule` only inside `apply_scope()`, which the helper opens.

**Impact.** A process that can read the endpoint file can ask a running helper to outbound-block any existing program, including `MsMpEng.exe`, without the dual gate. The installer does not start this helper. It is not a SYSTEM service. The risk becomes real if an operator runs the stub elevated.

**Next action.** hold the SYSTEM service. fix-now, when touching the helper, refuse the same protected basenames the agent handler refuses, and stop writing the token into a world-readable JSON file. Do not elevate the resident task to avoid building the service (`agent/privilege/helper.py` module doc).

### LOW — `python3.12` is not a protected process name

**Evidence.** `agent/modules/resource_advisor.py` `SYSTEM_PROTECTED` includes `python.exe`, `pythonw.exe`, `python3`, `python3.exe`, `python`, and not `python3.12`. `docs/TRUST_GATES.md` P5 box records a Linux failure of `test_close_pids_refuses_protected_target` when the interpreter name is `python3.12`: the refusal text is an identity mismatch, so the assertion `"protected" in msg` fails. `close_pids` still returns failure when `observed_at` is missing (`agent/modules/resource_advisor.py` around the identity check). This cloud host’s name is `python3`, so the test passed here. Windows CI on `4dd62e0` did not fail this test.

**Impact.** A user-approved close whose live image name is `python3.12`, with a fresh identity bundle, is not refused by the protected-name set. Autonomous close stays off (`USER_APPROVED_ONLY`).

**Next action.** discuss. Add versioned interpreter names, or treat a basename prefix `python` as protected, and fix the test so it does not depend on the host’s `psutil` name. Do not weaken the identity check.

### LOW — Optional hosts tool can block a MAPS name that is not on the safe list

**Evidence.** `config/telemetry-domains.txt` does not list `wdcp.microsoft.com`, SmartScreen, or Windows Update hosts. `scripts/hardening-common.ps1` `Test-IsUpdateSafe` keeps `mp.microsoft.com`, `windowsupdate.com`, `update.microsoft.com`, `download.microsoft.com`, `delivery.mp.microsoft.com`, and `settings-win.data.microsoft.com`. It does not name Defender MAPS hosts. `agent/modules/microsoft_guard.py` ignores legacy “block telemetry” flags and only recommends. `agent/modules/privacy_assistant.py` refuses to turn a MAPS / Windows Update / CRL / broad Microsoft name into a firewall rule. Installer has no `Add-MpPreference`.

**Impact.** Default install does not block MAPS. A hand-edited domain list plus `harden-once.ps1 -Apply` can sink a MAPS hostname. That script is not the resident.

**Next action.** discuss. Add the documented MAPS and SmartScreen hosts to the update-safe set before any domain list grows. Do not add an `ExclusionPath` to compensate.

### LOW — Post-registration Highest ACL check samples sentinels

**Evidence.** `installer/common.ps1` `Protect-DvielleInstallForElevation` walks the tree, refuses reparse points, and sets the elevation ACL on each file. `Test-DvielleElevatedTree`, used again in `installer/install-dvielle.ps1` before `Enable-ScheduledTask` when `-RunLevel Highest`, checks `agent\main.py`, the two venv launchers, `site-packages` if present, and the root. It does not re-walk. Default `-RunLevel` is `Limited`. `installer/elevate.ps1` elevates the installer process, not the resident task.

**Impact.** A file created after the walk and before enable could be writable under a Highest task. Elevated unattended use is already documented as not recommended. Field proof of the live ACL is UNCHECKED (`docs/CLAIMS.md` leftover 2, `docs/TRUST_GATES.md` empty box).

**Next action.** field-prove on the laptop. Until that prove exists, do not recommend `-RunLevel Highest`. A full re-walk at enable time is reasonable later. Do not change the default to Highest.

### INFO — Installer is not an atomic package rollback

**Evidence.** `docs/LAPTOP_ONLY.md`: a failed update can leave startup disabled and partially copied files; configuration is preserved; copying a tree does not refresh `.venv`. `installer/install-dvielle.ps1` re-syncs `.[windows,chat]` with `--upgrade-strategy only-if-needed` before the task is enabled, and disables the task if `verify_runtime.py` fails.

**Impact.** Operators who file-copy over `C:\DVILLIE` and skip the installer keep a stale environment. That is documented. It is still easy to miss because the page header says 1.6.0.

**Next action.** hold a transactional installer. fix-now the page header so it says 2.3.1.

---

## Matrix: spec promise vs implementation vs live-prove

| Promise (spec / claims) | Implementation on `4dd62e0` | Live-prove |
|---|---|---|
| Do not disable real-time protection to replace Defender. No install-time `ExclusionPath`. | No `ExclusionPath` / `Add-MpPreference` in installer or collectors. `Set-MpPreference` exists only in `agent/modules/prevention_apply.py` for one ASR id or one CFA mode, behind `require_cortex_mutate`, then a second `Get-MpPreference`. Health reader is read-only. | UNCHECKED. Linux tests reject the strings. No laptop `Get-MpComputerStatus` in this audit. |
| Engine freshness UNKNOWN. | `agent/modules/defender_health.py` stores `AMEngineVersion` and sets `engine_freshness` UNKNOWN. No catalog compare. | UNCHECKED, and the code agrees. |
| Home: Sandbox UNAVAILABLE, App Control authoring UNAVAILABLE. ASR and CFA edition-supported. SAC is a probe. | `agent/edition_matrix.py` forces those Home cells. SAC DWORD 0/1/2 mapped; anything else UNKNOWN. | UNCHECKED on a physical Home PC. `CloudEdition` cell is the open honesty question above. |
| ASR: two standard rules may move Audit → Block; WMI and other rules are not blanket-Blocked. CFA is a modification shield, not exfil. | `agent/modules/prevention.py` `WMI_GUID` `block_allowed` stays false. CFA copy states modification / boot-sector. Apply path re-reads. | UNCHECKED live preference write. |
| Firewall assist is not a second engine, not leakproof, does not stop MpsSvc. Success is the second `Get-NetFirewallRule`. | Observe script has no `New-NetFirewallRule`. Apply script is helper-scoped. One-family copy warns. | UNCHECKED under a third-party VPN. |
| Open unfamiliar: Pro+ `WindowsSandbox.exe` plus `.wsb` networking Disable and one read-only folder. Home checklist only. No WDAG, no Hyper-V substitute. | `agent/modules/sandbox.py`. Experience resolve on Home calls `observe_sandbox("Home")` and ignores a forged READY offer (`tests/test_worldclass_p5.py`). | UNCHECKED guest network and Group Policy override. Code names both as unread. |
| Privacy: Required diagnostics. Home/Pro cannot claim Security=Off. Do not block MAPS, Windows Update, or CRL by default. | `agent/modules/privacy_assistant.py`. Second read required. Broad Microsoft names create no rule. | UNCHECKED live registry write. |
| Passkeys: RP-scoped guidance. No phishing-impossible badge. Checklist marks do not change accounts. | `agent/modules/passkeys.py` `phishing_impossible: false`, `badge: None`, `accounts_changed: false`. | UNCHECKED that a site offers a passkey. The product does not claim it checked. |
| Experiences: Everyday quiet observation; Sensitive critical auto-protect; no auto CLOSE_PROCESS; proposals `applied: false`. | Alert floor and denylist locks hold. Severity floor now enforced in the gate (this change). Promotion snapshot caveat above. | UNCHECKED on a resident UI. |
| No privileged auto-update until TUF verifies root, timestamp, snapshot, targets. On failure keep the last good file. | `PRIVILEGED_AUTO_UPDATE = False`. Client is local-directory only. Package bytes stay on `_Stop`. Root metadata is persisted before the final root freeze check, which matches TUF 1.0.36 steps 5.3.7–5.3.10. | UNCHECKED live binary attestation. Do not claim the process was measured. |
| KEV/OSV local, missing file is `intel: unavailable`. abuse.ch not bundled. | `agent/intel/`. Fetch off unless a caller enables it. Auth-Key is not saved. | UNCHECKED against a live CISA download. |
| Dual mutate gate. Level ≥ 3 decision saved before the handler. | `agent/policy/cortex.py` `_persist_mutating` and `ActionExecutor._decision_saved`. `BLOCK_IP` has no product writer in `DualGate`. `store.block_ip` is a SQLite row, used by tests, not a firewall rule. | UNCHECKED on Windows SQLite under the resident. |
| Resident task Limited. Highest only after ACL lockdown. Elevated unattended not recommended. | `installer/install-dvielle.ps1` default `Limited`. Refuses Highest if lockdown or the sentinel re-check fails. | ACL field prove UNCHECKED. |
| `verify_runtime` after a real resident start. | 2.3.1 accepts a venv base-interpreter image in `sys.base_prefix` or `base/bin` only while `sys.prefix != sys.base_prefix`, plus heartbeat, create time, interpreter name, and `-m agent.main`. Fixture: `tests/test_verify_runtime.py`. | UNCHECKED. The fixture is not a resident start. |
| CPU contract: measured scheduling on the resident; Job Object cap only when the helper assignment reports applied. | `agent/cpu_contract.py` sets `applied: True` only after `AssignProcessToJobObject` succeeds. | UNCHECKED on RDS/DFSS. |

---

## Explicit leftovers (still UNCHECKED or out of this version)

These are already named in `docs/CLAIMS.md` and `docs/TRUST_GATES.md`. They are not done.

1. Live Windows resident `python scripts/verify_runtime.py` after a real logon task start.
2. Elevated ACL field prove on the target PC. Elevated unattended / Highest stays not recommended.
3. Named-pipe SYSTEM helper. The pipe module is an in-process SDDL contract. The process that listens is the loopback stub.
4. Privileged auto-update. TUF verification does not turn it on. No GitHub Release updater.
5. Live binary attestation of the running process. The TUF hash is metadata.
6. Engine freshness versus a Microsoft catalog. UNKNOWN.
7. Smart App Control reversibility without a reset. UNKNOWN on the locked Learn brief.
8. CFA read or exfiltration blocking. Not claimed.
9. Full VPN and IPv6 leakproof behavior for every client. UNKNOWN.
10. abuse.ch dumps inside the product. Not shipped.
11. AMTSO efficacy percentages. Not claimed. A features check would prove wiring, not a detection rate.
12. Camera in-use on Windows. Collector stays unknown.
13. Footprint collector. Live hits stay empty. Remote rows are drills.
14. `BLOCK_IP` OS writer. Not registered. `scripts/block-ip.ps1` is demoted and not called by `DualGate`.
15. Windows 11 SE / `CloudEdition` matrix cell. Not field-proved.
16. Green `ci / test` on 2.3.1. Run `36599565020` failed.

---

## What is healthy and should not be “fixed” into a regression

- **No `ExclusionPath`.** Do not add one so Defender will “stop scanning the agent.” That is the trust-boundary carve-out the installer tests exist to prevent.
- **Do not turn real-time protection off** or ship a second antivirus engine.
- **Resident RunLevel stays Limited.** `elevate.ps1` must keep elevating only the installer. Do not flip the default to Highest because the ACL walker exists. The field prove is empty.
- **Dual gate stays the only OS mutate path.** ASR, CFA, firewall, privacy, sandbox, temp delete, startup disable, and close all go through it. Auto-protect cannot issue ASR, CFA, sandbox, privacy, restrict-network, or CLOSE_PROCESS.
- **CFA copy stays a modification shield.** Do not add “stops ransomware reads” or “stops exfil.”
- **Home sandbox stays a checklist.** Do not start `WindowsSandbox.exe`, WDAG, or `New-VM` on Home. Do not call a normal window a sandbox.
- **Passkeys stay guidance.** Do not add a phishing-impossible badge, browser automation, or account mutation. RP scope is not a promise about stolen cookies or SMS recovery.
- **TUF failure keeps the previous package file.** Do not “fix” root handling by refusing to persist an intermediate root before step 5.3.10. That order is the spec. Do not enable privileged auto-update because verification exists.
- **MAPS stays reachable by default.** Do not add a firewall rule for Defender cloud, Windows Update, or CRL when a user asks to “block Microsoft.”
- **WMI ASR rule stays Audit-only.** Do not blanket-Block the catalog.
- **Helper stays a stub until a reviewed service exists.** Do not silently promote it to SYSTEM, and do not raise the scheduled task to Highest as a shortcut.
- **Unknown stays unknown.** Partial Defender reads, missing intel files, unread guest networking, and a missed Job Object assignment must keep saying so.
- **`python3` close refusal on this host is not a license to delete the identity check.** The `python3.12` test gap is a denylist hole under user approval, not a reason to auto-close interpreters.

---

## Coverage

| Dimension | Result |
|---|---|
| Honesty / claims drift | Findings above. TUF POUF sentence corrected. Historical spec sections still easy to misread. |
| Security regressions | No ExclusionPath, no MAPS block in the resident, no Highest default. Helper token file and CloudEdition cell are the open risks. |
| Features marked done | P0–P5 wiring matches the spec, with the Everyday-proposal wording gap and the severity-floor hole (fixed here). |
| Dual-gate holes | Persist-before-mutate holds. Severity floor did not; it does after this change. |
| Install / update | Non-atomic copy documented. 2.3.1 re-syncs dependencies before enable. Header still says 1.6.0. |
| Tests | Linux after the fix: 407 passed, 13 skipped. Windows CI on the parent commit: 1 failed, 418 passed. |
| Spec / CLAIMS / TRUST_GATES | Locks agree. Trust-gate green boxes are 2.3.0-era. 2.3.1 CI is red and not recorded there. |
| UNCHECKED field proves | Left unchecked. |
| Home vs Pro matrix | Home cells match Learn. `cloudedition` does not match the Sandbox Yes table. |
| Passkeys / experiences | No badge. Severity floor fixed. Promotion snapshot still lists ASR/CFA options in Everyday. |
| Privileged helper | Stub, not a service. Pipe ACL is not the listener. |
| Intel / TUF | Local, fail closed, auto-update off. POUF doc corrected. |
| Defender orchestration | Read health, gate ASR/CFA, no exclusion, no realtime disable. |
| CI / docs debt | Run 36599565020 red. Master architecture map is stale. |

Futuristic vision: a later resident could attach a measured engine-freshness and process measurement beside the TUF metadata hash, still fail-closed, without ever calling that pair a detection rate.
