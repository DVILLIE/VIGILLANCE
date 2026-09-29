# Trust gates

Pass/fail checklist for a DVielle change. Version 1.9.0 ships P1 on top of the 1.8.0 P0 observe path. Boxes are for a human or CI run against the tree that is about to ship.

Authority for claim language: `docs/FUNCTION_SPEC.md` (v0.9.1, 2026-09-29) and the primary-source brief of that date. A green box means the check was actually run. An empty box means it was not.

## Run on every P0 change

- [x] `python -m pytest -q` — fixture tests pass, including Home sandbox UNAVAILABLE, access-denied partial coverage, and MAPS copy that does not recommend blocking Defender cloud endpoints. Linux run on 2026-09-29 for 1.9.0: 338 passed, 13 skipped (the skipped tests are the existing Windows-only cases). The 1.8.0 run on the same day was 308 passed, 13 skipped.
- [x] `python scripts/smoke_test.py` — imports and config identity only; collectors are not started. Passed on the same Linux run.
- [ ] `python scripts/verify_runtime.py` — after a real resident start on Windows, the heartbeat and process identity match. A Linux or CI unit run does not satisfy this box
- [x] ExclusionPath contract — installer and the P0 collectors contain no `Add-MpPreference ExclusionPath` (see `tests/test_install_acl_contract.py` and `tests/test_worldclass_p0.py`). Those tests passed in the run above.
- [x] Edition honesty — Home matrix: Windows Sandbox UNAVAILABLE, App Control authoring UNAVAILABLE, ASR and CFA edition-supported, Smart App Control probe-only. The console evidence strip shows the same states. Covered by `tests/test_worldclass_p0.py`.
- [x] Claims → Assumptions → Evidence — each FREE pillar in `docs/FUNCTION_SPEC.md` §1.1 has all three. Unknown stays unknown. Engine freshness stays UNKNOWN. CFA is not described as a read or exfiltration control

## Explicitly unchecked until built

- [ ] Attestation checksum — not implemented. Do not claim a signed measurement of the agent binary
- [ ] TUF — not implemented. Do not auto-update a privileged agent from a GitHub Release asset. Manual update remains the path until root, timestamp, snapshot, and targets reject rollback, freeze, and mix-and-match in fault-injection tests

## P1 (1.9.0) — recorded on the Linux run above

- [x] `python -m pytest -q` includes `tests/test_worldclass_p1.py`: Home and Pro share the ASR path, access denial stays partial, WMI and other rules are not blanket-Blocked, CFA copy is a modification shield, recovery states are independent, and the apply path is dual-gated. Same Linux run as above: 338 passed, 13 skipped
- [x] ASR/CFA writes are absent from the observe script. `security.py` does not call `Set-MpPreference`. No `ExclusionPath` and no ASR path exclusion in the P1 modules. Covered by `tests/test_worldclass_p1.py` in that run
- [x] Auto-protect cannot issue `SET_ASR_RULE` or `SET_CFA_MODE`. A preference change counts only when the second read matches. Covered by `tests/test_worldclass_p1.py` in that run

## Still true, not new work

- Dual mutate gate still wraps every OS change. 1.9.0 adds ASR and CFA handlers to that same gate. It does not add a second mutate path
- Resident scheduled task stays RunLevel Limited. Elevated unattended use stays held
- No offensive tools
- Camera in-use on Windows and the live footprint collector still do not invent evidence
- P2 remains: firewall app-rule assistant, privileged helper, published CPU contracts. Sandbox `.wsb`, TUF, intel feeds, and the privacy assistant are still later
