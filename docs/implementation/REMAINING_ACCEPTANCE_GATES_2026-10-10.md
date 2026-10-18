# D’Vielle Remaining Acceptance Gates

**Historical checkpoint:** the current authoritative ledger is [Current acceptance and implementation plan, 2026-10-11](CURRENT_ACCEPTANCE_AND_IMPLEMENTATION_PLAN_2026-10-11.md). Identities and pending statuses below describe earlier checkpoints.

This ledger describes the current evidence after the administrative-actions deployment. Completion of one bounded acceptance experiment does not certify every variant.

| Area | Verified evidence | Remaining acceptance |
|---|---|---|
| Network enforcement | Actual IPv4 executable-image rule blocked new TCP and reset existing TLS; owned restoration restored connectivity | Routed IPv6 baseline; UDP/QUIC; VPN/proxy paths; child images; conflicting policies; independently measured packet outcomes |
| Upgrade and recovery | Real worker exit 23 after file replacement; durable journal; complete predecessor identity restored; helper/task restarted | Power loss; corruption; other interruption points; multi-version upgrade and rollback |
| GUI approval and recovery | Installed production widgets; missing scope and invalid operation rejected without elevation; closed consent contract; protected deployment | Human UAC/scope approval/apply/restore journey; cancellation races; keyboard/screen-reader/scaling acceptance |
| Performance and privacy | Existing resource/privacy reports and controls; current tests retained | Controlled foreground workload comparisons; battery/offline measurements; independent privacy observation |
| Attack-path decisions | Existing assessed controls and bounded action contract | Evidence-supported consequential-path evaluation and safe automation acceptance across representative attacks |
| Optional AI | Existing implementation and recorded boundaries | Exact real model/runtime isolation, provenance, resource costs and evaluation; no invented model results |
| Post-quantum | Verified certificate/hostname/Finished handshake; observed X25519MLKEM768 on recorded endpoints | Enforced hybrid-only adapters, downgrade rejection, authenticated PQ identity and real key lifecycle; observed certificates remain classical |
| Public distribution | Protected local runtime hashes; exact dependency/license inventory; documentation | Authenticated publisher/update roots; wrapper/rollback/uninstall acceptance; unresolved notices; independent multi-build pilots |

The latest installed runtime has 5,792 files and SHA256 4f2ceb115cdc80af78ddfd20efcc76fd84f7717070785d113a456608ef052bbc. It is a locally approved deployment, not an authenticated public release. Private configuration remains inaccessible to the normal observer; this is expected access separation, and the independent readable inventory is recorded separately. No acceptance is inferred from an inaccessible private file.

Evidence documents: ADMINISTRATIVE_ACTIONS_AND_INTERRUPTION_RECOVERY_2026-10-10.md; PRODUCT_COMPLETION_CHECKPOINT_2026-10-10.md; ACTUAL_IMAGE_NETWORK_RESOLUTION_2026-10-10.md; TLS_KEY_EXCHANGE_ADVANCEMENT_2026-10-10.md; ../legal/THIRD_PARTY_NOTICE_REVIEW_2026-10-10.md.

## New source progress, not installed

The scoped hybrid-only gate and TLS 1.2 parser repair now pass actual endpoint observations and a 704-test suite. Deployment approval was canceled. The narrow installed-helper UDP acceptance launch was canceled separately; only normal-user DNS preflight succeeded. Neither cancellation closes an acceptance gate. The current installed digest remains the 5,792-file identity above. See SAME_DAY_HYBRID_GATE_AND_UDP_PROGRESS_2026-10-10.md.


## Latest verified checkpoint: assessment and consent correction

The hybrid assessment increment is installed and independently verified (5,792 files; ca393448f5436bc26376f2146d73ca9e3400929543d8baca00fbf538a66a5fe8). The subsequent ASR reporting and consent prompt corrections passed 704 tests and are staged, not installed. Actual UDP packet attribution and the human approval/apply/recover journey remain unaccepted. See [actual assessment review and candidate boundary](ASSESSMENT_REVIEW_AND_CONSENT_CORRECTION_2026-10-10.md).

## Live consent receipt defect resolved and actual journey passed

After human approval, the client failed with Windows error 5 while inspecting the security descriptor of the Windows Temp receipt ancestry. The actual diagnostic is preserved in `ACTUAL_CONSENT_FAILURE_DIAGNOSTIC_2026-10-10.json`. Receipts now reside beneath the protected installed application directory, with their existing Administrator/SYSTEM write and bound-user read permissions retained. The one-file correction is installed and independently verified: 5,792 files, runtime digest `090f92667f382616c836b54a4fefe1adb8243de2c94d4b2c60c4aabba66d39e9`. Relevant tests: 24 passed.

The first receipt-fixed traffic test targeted python.exe while its GUI probes actually ran under pythonw.exe. That rule was restored, and the inconclusive result is retained. The acceptance driver now observes its actual OS process image rather than hardcoding an executable.

The corrected actual installed GUI journey passed: baseline connection succeeded; human-approved restriction of pythonw.exe to 151.101.0.223/32 produced Windows error 10013 on both real TCP probes; human-approved recovery reported owned-rule cleanup verified; the subsequent connection succeeded. No callback errors were recorded. Evidence: `ACTUAL_INSTALLED_GUI_ACTION_EXACT_IMAGE_2026-10-10.json`, operation `6ef6945266d04b88b98a4d2500db70ba`. This verifies that one IPv4 TCP scope and the human approval/apply/recover flow; it does not establish UDP, IPv6, VPN, QUIC, accessibility, or worldwide release acceptance.
