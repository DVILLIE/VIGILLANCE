# D’Vielle — Actual Assessment Review and Consent Correction

## Verified assessment

The actual user assessment `9fce7e0e-f0e6-4a6f-af43-687bca8b351c` completed on 10 October 2026 with 21 review findings and no security mutations. Defender antivirus and real-time protection were enabled, and all three firewall profiles were enabled. Controlled Folder Access was disabled. Listener records are observations; they do not establish compromise or external reachability.

Three actual assessment histories were copied using a consistent SQLite backup into the installed application's assessment database. Run identifiers, timestamps and states matched before and after preservation; the original database remains intact. See `ACTUAL_USER_ASSESSMENT_HISTORY_PRESERVATION_2026-10-10.json`.

## Reporting defect and correction

The engine omitted ASR action 5 from its review condition. Microsoft documents action 5 as NotConfigured and action 6 as Warn. The corrected condition includes action 5, so the vulnerable-driver and LSASS protection rules are now flagged when not configured for blocking. The saved original assessment is not rewritten. A new actual read-only source assessment confirms both findings; see `ACTUAL_CORRECTED_ASR_ASSESSMENT_2026-10-10.json`.

Reference: [Microsoft Set-MpPreference](https://learn.microsoft.com/en-ca/powershell/module/defender/set-mppreference?view=windowsserver2022-ps).

## Consent journey and correction

The actual GUI action journey timed out without a verified approval or applied restriction. It produced no recorded mutations. This is not evidence of successful human approval, nor proof of the timeout's cause.

The candidate mediator now displays its review window, defaults confirmations to No, and closes an unanswered prompt after 240 seconds or when the original requesting process exits. The client includes the protected receipt location in timeout diagnostics. Windows elevation and explicit security-scope consent remain required.

## Tested candidate and installed boundary

The assessment and consent regression suite passed: **704 passed**, with nine Pillow warnings. Evidence: `ASSESSMENT_AND_CONSENT_FINAL_REGRESSION_2026-10-10.txt`.

The r12 payload is staged in `C:\Program Files\DVielleStage-c29a47dab27f49ccae528c560517fb00`. Its independent plan changes exactly three application Python files. Candidate full-runtime digest: `3cbec108d10c627f7bf02db6d6e9239730e6685a583570e884d10a599efd70bd`.

**These corrections are staged, not installed.** The verified installed runtime remains 5,792 files with digest `ca393448f5436bc26376f2146d73ca9e3400929543d8baca00fbf538a66a5fe8`. It already includes the hybrid-only TLS assessment gate. No further elevation was launched after the user said they were going out.

## Remaining acceptance

The actual UDP trial observed two timeouts during a configured restriction and successful matching DNS responses before and after restoration. The owned rule was restored. Timeouts alone do not attribute packets to that rule, so UDP enforcement acceptance remains unproven. The actual human approval/apply/recover GUI journey also remains unaccepted. Broader release gates remain recorded in `REMAINING_ACCEPTANCE_GATES_2026-10-10.md`.

## Activation after the user returned

The user-approved update completed with `activated_identity_verified`. An independent normal-user inventory matched all 5,792 runtime files to digest `3cbec108d10c627f7bf02db6d6e9239730e6685a583570e884d10a599efd70bd`. The ASR reporting and consent prompt corrections are now installed; the earlier staged-only statement describes the pre-approval checkpoint. The helper service and resident task are running. No firewall mutations occurred during this update. Receipts: `PROTECTED_ASSESSMENT_CONSENT_INCREMENT_RESULT_2026-10-10.json` and `POST_ASSESSMENT_CONSENT_ACTIVATION_RUNTIME_CHECKS_2026-10-10.json`.

A separate actual GUI approval/apply/recover acceptance journey was launched with fresh evidence in `ACTUAL_INSTALLED_GUI_ACTION_JOURNEY_RETRY_2026-10-10.json`. Its launch alone is not acceptance.

## Live consent receipt defect resolved and actual journey passed

After human approval, the client failed with Windows error 5 while inspecting the security descriptor of the Windows Temp receipt ancestry. The actual diagnostic is preserved in `ACTUAL_CONSENT_FAILURE_DIAGNOSTIC_2026-10-10.json`. Receipts now reside beneath the protected installed application directory, with their existing Administrator/SYSTEM write and bound-user read permissions retained. The one-file correction is installed and independently verified: 5,792 files, runtime digest `090f92667f382616c836b54a4fefe1adb8243de2c94d4b2c60c4aabba66d39e9`. Relevant tests: 24 passed.

The first receipt-fixed traffic test targeted python.exe while its GUI probes actually ran under pythonw.exe. That rule was restored, and the inconclusive result is retained. The acceptance driver now observes its actual OS process image rather than hardcoding an executable.

The corrected actual installed GUI journey passed: baseline connection succeeded; human-approved restriction of pythonw.exe to 151.101.0.223/32 produced Windows error 10013 on both real TCP probes; human-approved recovery reported owned-rule cleanup verified; the subsequent connection succeeded. No callback errors were recorded. Evidence: `ACTUAL_INSTALLED_GUI_ACTION_EXACT_IMAGE_2026-10-10.json`, operation `6ef6945266d04b88b98a4d2500db70ba`. This verifies that one IPv4 TCP scope and the human approval/apply/recover flow; it does not establish UDP, IPv6, VPN, QUIC, accessibility, or worldwide release acceptance.
