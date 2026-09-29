# Trust gates

Pass/fail checklist for a DVielle change. Version 2.2.0 ships P4 on top of the 2.1.0 P3 path. Boxes are for a human or CI run against the tree that is about to ship.

Authority for claim language: `docs/FUNCTION_SPEC.md` (v0.9.3, 2026-09-29) and the primary-source brief of that date. A green box means the check was actually run. An empty box means it was not.

## Run on every P0 change

- [x] `python -m pytest -q` — fixture tests pass, including Home sandbox UNAVAILABLE, access-denied partial coverage, and MAPS copy that does not recommend blocking Defender cloud endpoints. Linux run on 2026-09-29 for 1.9.0: 338 passed, 13 skipped (the skipped tests are the existing Windows-only cases). The 1.8.0 run on the same day was 308 passed, 13 skipped. The 2.0.0 run is recorded in the P2 section.
- [x] `python scripts/smoke_test.py` — imports and config identity only; collectors are not started. Passed on the same Linux run.
- [ ] `python scripts/verify_runtime.py` — after a real resident start on Windows, the heartbeat and process identity match. A Linux or CI unit run does not satisfy this box
- [x] ExclusionPath contract — installer and the P0 collectors contain no `Add-MpPreference ExclusionPath` (see `tests/test_install_acl_contract.py` and `tests/test_worldclass_p0.py`). Those tests passed in the run above.
- [x] Edition honesty — Home matrix: Windows Sandbox UNAVAILABLE, App Control authoring UNAVAILABLE, ASR and CFA edition-supported, Smart App Control probe-only. The console evidence strip shows the same states. Covered by `tests/test_worldclass_p0.py`.
- [x] Claims → Assumptions → Evidence — each FREE pillar in `docs/FUNCTION_SPEC.md` §1.1 has all three. Unknown stays unknown. Engine freshness stays UNKNOWN. CFA is not described as a read or exfiltration control

## Explicitly unchecked until built

- [ ] Live binary attestation — not implemented. Do not claim a signed measurement of the running agent. 2.1.0 displays the TUF package hash after verification. That is metadata attestation, not a measurement of the process
- [x] TUF metadata path — offline client verifies root, timestamp, snapshot, and targets. Fault injection for rollback, freeze, a bad hash, mix-and-match, and a bad signature keeps the previous file. Privileged auto-update stays off. No GitHub Release updater. Covered by `tests/test_worldclass_p3.py` in the P3 run below

## P1 (1.9.0) — recorded on the Linux run above

- [x] `python -m pytest -q` includes `tests/test_worldclass_p1.py`: Home and Pro share the ASR path, access denial stays partial, WMI and other rules are not blanket-Blocked, CFA copy is a modification shield, recovery states are independent, and the apply path is dual-gated. Same Linux run as above: 338 passed, 13 skipped
- [x] ASR/CFA writes are absent from the observe script. `security.py` does not call `Set-MpPreference`. No `ExclusionPath` and no ASR path exclusion in the P1 modules. Covered by `tests/test_worldclass_p1.py` in that run
- [x] Auto-protect cannot issue `SET_ASR_RULE` or `SET_CFA_MODE`. A preference change counts only when the second read matches. Covered by `tests/test_worldclass_p1.py` in that run

## P2 (2.0.0) — recorded on the Linux run below

- [x] `python -m pytest -q` includes `tests/test_worldclass_p2.py`: firewall observation does not stop MpsSvc, proposals stay unapplied, a verified `Get-NetFirewallRule` transcript is required, IPv4/IPv6 and VPN copy is not leakproof, undefined helper operations are refused, the resident task is not switched to Highest, and the CPU contract does not terminate other processes. Linux run on 2026-09-29 for 2.0.0: 355 passed, 13 skipped (the skipped tests are the existing Windows-only cases).
- [x] Firewall writes are absent from the observe script. The apply script is reached only from the helper dispatcher. No `ExclusionPath`, no MAPS block, no GitHub auto-update in the P2 modules. Covered by `tests/test_worldclass_p2.py` in that run.
- [x] Auto-protect cannot issue `safety.restrict_network`. A firewall change counts only when the second read matches. A one-family rule is warned and is not called leakproof. Covered by `tests/test_worldclass_p2.py` in that run.

## P3 (2.1.0) — recorded on the Linux run below

- [x] `python -m pytest -q` includes `tests/test_worldclass_p3.py`: Home Sandbox offer UNAVAILABLE with a SAC/ASR/CFA/Firewall checklist, Pro launch only through `WindowsSandbox.exe` and a `.wsb` that disables networking and maps one read-only folder, unobserved guest networking stays LIMITED, auto-protect cannot open a sandbox, TUF rollback/freeze/bad-hash/mix-and-match keep the previous file, and the pipe ACL refuses undefined operations. Linux run on 2026-09-29 for 2.1.0: 370 passed, 13 skipped (the skipped tests are the existing Windows-only cases). `python scripts/smoke_test.py` passed on that run. `ruff check agent dvielle tests scripts/smoke_test.py scripts/verify_runtime.py --select E9,F63,F7,F82` passed.
- [x] No `ExclusionPath`, no MAPS endpoint block, and no `api.github.com` download in the P3 modules. WDAG and `New-VM` are not launch paths. The resident scheduled task default stays RunLevel Limited. Covered by `tests/test_worldclass_p3.py` in that run.
- [x] A verified network probe is not a malware-escape claim, and Group Policy override of `.wsb` settings is named as unread. Privileged auto-update remains false. Live binary attestation remains UNCHECKED.

## P4 (2.2.0) — recorded on the Linux run below

- [x] `python -m pytest -q` includes `tests/test_worldclass_p4.py`: a missing KEV/OSV file is `intel: unavailable`, an invalid schema invents no hits, a KEV name overlap is a candidate, an OSV hit needs a comparable version, fetch and abuse.ch stay off unless explicitly enabled, Home cannot write Security=Off, a privacy change counts only on the second read, and a MAPS/Windows Update/CRL name creates no firewall rule. Linux run on 2026-09-29 for 2.2.0: 382 passed, 13 skipped (the skipped tests are the existing Windows-only cases). `python scripts/smoke_test.py` passed on that run. `ruff check agent dvielle tests scripts/smoke_test.py scripts/verify_runtime.py --select E9,F63,F7,F82` passed.
- [x] No `ExclusionPath`, no `Add-MpPreference`, and no `api.github.com` download in the P4 modules. The resident collector does not call the feed downloader. abuse.ch is not bundled. Covered by `tests/test_worldclass_p4.py`.
- [x] Home Sandbox stays UNAVAILABLE. CFA copy stays a modification shield. Privileged auto-update stays false. Passkeys, activity modes, and a SYSTEM helper stay later.

## Still true, not new work

- Dual mutate gate still wraps every OS change. 2.1.0 adds `OPEN_SANDBOX` for Open unfamiliar. 2.2.0 adds `SET_PRIVACY_CHOICE` for one privacy setting. Auto-protect cannot issue either. Firewall app rules still use `RESTRICT_NETWORK`
- Resident scheduled task stays RunLevel Limited. Elevated unattended use stays held. The helper is not a SYSTEM service and not a Highest scheduled task
- No offensive tools
- Camera in-use on Windows and the live footprint collector still do not invent evidence
- P5 remains: passkey education and Everyday/Sensitive modes. Claims/Assumptions page polish and a named-pipe SYSTEM helper stay later. abuse.ch stays out of the bundle
