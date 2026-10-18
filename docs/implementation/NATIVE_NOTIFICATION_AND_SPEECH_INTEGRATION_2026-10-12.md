# D'Vielle native notification and speech integration

## Implemented changes

Guardian notifications now use the existing pystray Windows backend. A ready GUI
tray is reused; headless notifications create a temporary branded tray icon and
remove it after the bounded display interval. One daemon worker serializes a queue
of eight notifications. A full queue logs the message and returns without blocking
the monitoring loop. Windows notification preferences can suppress visibility;
queue admission is never described as confirmed delivery.

Speech retains Windows SAPI through pywin32 and removes the redundant pyttsx3
fallback. Voice language attributes are parsed as hexadecimal and support multiple
language identifiers. Spoken observations are explicitly plain text rather than
XML. The speech queue is bounded at sixteen messages and the GUI never waits for
queue capacity. If SAPI fails, the existing console remains usable and logs the
failure. No online speech service, new credential or security-policy change is used.

## Dependency verification

The first notification-only candidate still contained pypiwin32: inspection of
actual wheel metadata identified pyttsx3 as its remaining parent. That intermediate
candidate and preparation log are retained. The final native candidate removes
win10toast, pyttsx3, pypiwin32 and comtypes from its thirteen-wheel closure.

`dist/offline-dependencies-native-20261012/manifest.json` records exact wheel names,
versions, bytes, SHA256 and matching official PyPI metadata URLs. Every artifact
was checked against its version-specific PyPI record; the complete hashed closure
also resolved offline. This establishes artifact matching and dependency closure,
not publisher signing or complete legal clearance.

A separate new Python 3.14.8 environment was then installed from that hashed
offline candidate, followed by a no-dependency/no-build-isolation editable install
of the application. `pip check` reported no broken requirements and the application's
non-collecting smoke checks all passed. Its actual distribution inventory confirms
win10toast, pyttsx3, pypiwin32 and comtypes are absent; see
`ACTUAL_CLEAN_NATIVE_DEPENDENCY_ENVIRONMENT_2026-10-12.json`. This is a local
unprivileged clean environment, not a public installer or the protected resident
environment migration.

The source dependency declaration and Windows CI lock use this reduced dependency
set. Previously installed unused distributions are not deleted by an application
code increment; the installed notice inventory must continue to list them until a
separately verified environment migration removes them.

## Actual checks and evidence

- The Windows notification backend returned without captured errors in 2.178
  seconds. `ACTUAL_NOTIFICATION_BACKEND_2026-10-12.json` records the result.
  Human observation of notification visibility was not obtained.
- A real SAPI call successfully returned after speaking a short integration check.
  Human audio confirmation was not obtained.
- Focused checks cover tray reuse, unready/failing tray fallback, queue saturation,
  duration bounds, hexadecimal multilingual selection and COM cleanup on failure.
- The initial full integration regression recorded 718 passes and one legacy test
  failure: that test required blocking `Queue.put`. It was corrected to inspect
  the actual queued message while preserving the new nonblocking behavior.
  The failed report is retained; the final regression has a separate report.
  The final full suite passed **719 tests**, with nine existing Pillow deprecation
  warnings, in 61.52 seconds.

## Installation boundary

The candidate archive SHA256 is
`aec3a5722e0d829d12b6e757fa8cf48310c97964c8db6afdca24aee6a920c0b2`.
It was approved through Windows elevation and staged under
`C:\Program Files\DVielleStage-082723bb655241b5bcf36afa0d72ced0`.
That stage remains Administrator/SYSTEM-only. Planning reads the independently
hashed archive; activation checks the protected stage's ACL and exact bytes under
the approved administrator token. No permissions are weakened to read staging.

`PROTECTED_NATIVE_INCREMENT_PLAN_2026-10-12.json` binds the four production files
to their exact predecessor and successor hashes. The expected successor runtime
digest is `88ff60de375cb33a20ec59cdd85c0808122464532f03cd7942a28047e2830846`.
An expected digest is not an installation receipt. Activation is accepted only
after the protected worker receipt, independent inventory and resident/helper
health checks agree.

Those checks now agree: `PROTECTED_NATIVE_INCREMENT_RESULT_2026-10-12.json`
records `activated_identity_verified`, and
`ACTUAL_INSTALLED_NATIVE_INTEGRATION_2026-10-12.json` independently records the
expected successor digest across **5,796 files**. The helper and Limited resident
task were both running. Both notification and SAPI calls also returned successfully
from the installed interpreter and installed modules. Human visual/audio acceptance
remains explicitly unverified. Two initial launcher attempts stopped before
activation because the local wrapper placed a future import after other code;
the corrected wrapper compiles the immutable worker separately. The protected
failure diagnostic is retained. No product guard was disabled.

Source commit `4afcda39443a9b2015b474620f27b9ff13b3a2ef` was pushed to the
existing [draft PR 26](https://github.com/DVILLIE/VIGILLANCE/pull/26).
Only twelve explicitly selected source/configuration/test files were uploaded.
Machine reports, the local evidence bundle and private signing material were not
uploaded. [Hosted run 38166949351](https://github.com/DVILLIE/VIGILLANCE/actions/runs/38166949351)
completed successfully for the new source. Both hosted Windows regressions recorded
**694 passed, 25 explicit skips, zero failures/errors** out of 719 collected tests.
Both real GUI reports record `keyboard_routing_passed`. All four downloaded
XML/GUI result attestations were independently verified against the repository,
workflow, pull-request ref and exact run invocation. The evidence is retained in
`ACTUAL_REMOTE_NATIVE_ACCEPTANCE_2026-10-12.json` and the four corresponding
`NATIVE_REMOTE_ATTESTATION_*` records. The separate installer workflow still skips compilation under
the existing hold, so its green status does not prove a setup executable exists.

The public setup wrapper hold, isolated AI execution and other acceptance areas
remain open. This increment does not claim to finish those areas.

## Primary references

- [pystray notification and Windows thread behavior](https://pystray.readthedocs.io/en/latest/usage.html).
- [pystray notification lifecycle](https://pystray.readthedocs.io/en/latest/reference.html).
- [Microsoft SAPI Speak](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms723609%28v%3Dvs.85%29).
- [Microsoft SpVoice](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee125640%28v%3Dvs.85%29).
- [Microsoft hexadecimal and multilingual voice identifiers](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee125675%28v%3Dvs.85%29).
