# D’Vielle Same-Day Hybrid Gate and UDP Acceptance Progress

## Implemented and tested

The Advanced Ethical Hacking workspace adds **Test hybrid-only TLS gate** for one explicitly authorized HTTPS origin. Scope validation rejects non-boolean selection and hybrid requests outside the handshake-only path. The adapter requires TLS 1.3 and, after certificate, hostname and Finished verification, accepts only recognized ML-KEM hybrid exchange groups. Older protocols, classical groups and unknown groups fail closed. It sends no HTTP/application data and does not retry a weaker connection. This is an acceptance gate on D’Vielle’s selected connection; it does not reconfigure other Windows applications or establish post-quantum certificate authentication.

Actual Python.org and Wikipedia connections passed with X25519MLKEM768. Actual badssl.com baseline completed TLS 1.2, while the hybrid-required attempt failed with a TLS handshake alert and no fallback. These are recorded endpoint observations, not independent proof of adversarial downgrade resistance in every protocol or application.

The badssl baseline initially exposed a real parser defect: TLS 1.2 encrypted Finished records were interpreted as plaintext handshake lengths. The parser now stops parsing plaintext handshake messages when ChangeCipherSpec starts protected records. The corrected real TLS 1.2 handshake completed successfully. The original failed record is retained.

Full regression: **704 passed**, nine existing Pillow deprecation warnings, 79.33 seconds. Contract tests are labeled as such and are not substituted for actual endpoint observations.

## Protected deployment

The reviewed r11 archive contains 286 files, SHA256 fa75bb491b58a14fb536d65d238e37b14dae33c0c16453598314c846087bc7df. Windows-approved staging completed at C:/Program Files/DVielleStage-702c8bca42b24c65b08c14c4ddb2a322. The planned three-file increment has successor runtime SHA256 ca393448f5436bc26376f2146d73ca9e3400929543d8baca00fbf538a66a5fe8. Installation is not claimed without a successful protected activation receipt and independent whole-runtime hashing.

## UDP acceptance

A separate bounded acceptance driver sends a DNS question for www.python.org to one reviewed public resolver. It requires a matching successful baseline, temporarily requests the installed helper’s exact executable-image scope, tests two UDP requests, and conditionally restores the exact owned operation. A timeout alone is inconclusive: denial acceptance requires Windows error 10013. Lost helper replies are reconciled against the exact grant-bound operation before permission cleanup.

The actual normal-user preflight to 1.1.1.1 received a matching answer. The elevated test launch was canceled at Windows Administrator approval, so the installed-helper UDP experiment did not run and made no test mutation. It is not an accepted UDP protection result. No approval bypass or retry of that declined test was performed.

## Evidence and research

HYBRID_GATE_FINAL_REGRESSION_2026-10-10.txt; ACTUAL_HYBRID_GATE_PYTHON_ORG_2026-10-10.json; ACTUAL_HYBRID_GATE_WIKIPEDIA_2026-10-10.json; ACTUAL_CLASSICAL_BASELINE_BADSSL_CORRECTED_2026-10-10.json; ACTUAL_HYBRID_GATE_REJECTION_BADSSL_2026-10-10.json; ACTUAL_UDP_ACCEPTANCE_CANCELED_2026-10-10.json; PROTECTED_HYBRID_INCREMENT_PLAN_2026-10-10.json.

Primary references: [Python 3.14 TLS API and verification](https://docs.python.org/3.14/library/ssl.html), [Windows firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules), [Windows consent](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works).

All remaining gates in REMAINING_ACCEPTANCE_GATES_2026-10-10.md stay open unless explicitly superseded by fresh bounded evidence. Public-release, independent multi-Windows, power-loss, battery comparisons, optional-model evaluation and global post-quantum authentication are not declared completed today.

## Final observed deployment status

The separate protected activation launch was also canceled at Windows Administrator consent. No update process was created, and no activation is claimed. Independent hashing after cancellation still matches the previously installed 5,792-file identity 4f2ceb115cdc80af78ddfd20efcc76fd84f7717070785d113a456608ef052bbc. The helper was observed Running. Both declined actions remain recorded separately; neither was bypassed or repeated.

The new hybrid gate and parser repair are source-tested, live-endpoint-tested and staged, but **not installed**. Protected deployment remains dependent on the operator accepting the Windows approval for that reviewed increment.

Thirty actual resident-process samples completed, with sampled peak RSS sum 187,604,992 bytes across visible descendants. Shared pages can be counted more than once; this is not unique memory or a controlled performance comparison. A separate forty-checkpoint provenance observation saw pythonw.exe, powershell.exe and conhost.exe. The battery was present, at 100 percent and plugged in; no battery drain comparison was performed. These point observations do not close the performance/privacy release gate.


## Latest verified checkpoint: assessment and consent correction

The hybrid assessment increment is installed and independently verified (5,792 files; ca393448f5436bc26376f2146d73ca9e3400929543d8baca00fbf538a66a5fe8). The subsequent ASR reporting and consent prompt corrections passed 704 tests and are staged, not installed. Actual UDP packet attribution and the human approval/apply/recover journey remain unaccepted. See [actual assessment review and candidate boundary](ASSESSMENT_REVIEW_AND_CONSENT_CORRECTION_2026-10-10.md).
