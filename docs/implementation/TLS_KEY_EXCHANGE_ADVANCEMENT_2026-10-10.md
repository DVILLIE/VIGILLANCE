# D'Vielle negotiated TLS key exchange advancement

## Implemented capability

The capability is now installed in the protected application. The second backed-up
activation changed three application files and verified the entire 5,790-file
runtime against the independently derived digest
`9a79ee47c21f81e6577b143df75f46f69f5f89d1f0332c82147399d0d77a69aa`.
An independent ordinary-user inventory matched this digest afterward. The actual
installed assessment completed run `c10c28da-3fad-45e5-ad0d-32a8b2dd5004` and
measured X25519MLKEM768, with no policy mutations. Evidence is in
`ACTUAL_INSTALLED_TLS_ASSESSMENT_2026-10-10.json` and
`POST_TLS_ACTIVATION_RUNTIME_CHECKS_2026-10-10.json`.

The Ethical Hacking workspace now has a separate **Measure TLS key exchange**
action under **Authorized website**. It requires an HTTPS origin, an authority
reference and a fresh confirmation. It performs one verified TLS handshake, saves
the actual observed exchange group into the assessment ledger and shows the
result under Quantum readiness. It sends no HTTP request, follows no redirects
and changes no operating-system policy. The existing website HEAD review remains
a separate action.

The measurement follows the same immutable five-minute assessment scope, bounded
DNS resolution, address pinning, single-run lock, cancellation and redacted export
controls as other assessments. The TLS driver checks cancellation before opening
the connection, throughout the handshake and before publishing observations.
An in-flight socket wait may take until the bounded handshake deadline to return;
it does not represent instant cancellation of packets already sent.

## Technical resolution

Python's public SSL APIs do not directly return the negotiated TLS group.
The implementation uses public `ssl.MemoryBIO` and `SSLObject` APIs to drive the
actual installed TLS provider and parse only plaintext public ServerHello fields.
It handles record/message fragmentation, distinguishes HelloRetryRequest from
the final ServerHello, bounds input sizes and rejects malformed extension lengths.
The measured group is reported only after the TLS provider successfully verifies
the certificate, hostname and handshake Finished transcript. It does not infer
key exchange from a cipher-suite name or installed package version.

The application TLS context continues to suppress SSLKEYLOGFILE inheritance.
Neither traffic secrets nor private keys are saved. A separate optional command
line entry point is supplied in `scripts/observe_tls_key_exchange.py`.

## Actual results and contrary checks

Using the protected Python 3.14.8 runtime, actual connections to Python.org and
Cloudflare each completed TLS 1.3 and selected group **4588,
X25519MLKEM768**. The certificate keys were respectively RSA-2048 and P-256 EC.
These are hybrid post-quantum/traditional key exchanges with classical certificate
keys. Post-quantum certificate authentication was not established.

An actual negative-control connection to the Python.org endpoint used the
deliberately mismatched hostname `negative-control.foo.python.org`. The provider
rejected it with certificate verification code 62, hostname mismatch. The observer
did not emit a successful handshake observation.

The integrated source assessment completed run
`40eb69a6-8a7b-407e-be6a-e7837f48dbce`, measured X25519MLKEM768 and performed no
mutations. Its exported report removed the origin hostname. A real withdrawn Tk
workspace instantiated the new button; invoking it without an approved HTTPS
origin rejected the request and did not start a worker. This widget check is not
a completed Narrator, scaling or full user journey acceptance.

The full source regression passed **678 tests**, with nine existing Pillow
deprecation warnings, in 121.33 seconds. Application integration is in
`agent/assessment/tls_observer.py`, `agent/assessment/engine.py` and
`dvielle/gui/assessment.py`. The exact protected activation outcome is recorded
separately in `PROTECTED_TLS_INCREMENT_RESULT_2026-10-10.json` when available.

## Evidence files

- `ACTUAL_TLS_KEY_EXCHANGE_PYTHON_ORG_2026-10-10.json`
- `ACTUAL_TLS_KEY_EXCHANGE_CLOUDFLARE_2026-10-10.json`
- `ACTUAL_TLS_OBSERVER_NEGATIVE_CONTROL_2026-10-10.json`
- `ACTUAL_INTEGRATED_TLS_ASSESSMENT_2026-10-10.json`
- `TLS_OBSERVER_INTEGRATION_REGRESSION_2026-10-10.txt`
- `APPROVED_TLS_INCREMENT_PLAN_2026-10-10.json`
- `EXPECTED_TLS_INCREMENT_RUNTIME_2026-10-10.json`

This closes the absence of an actual negotiated-group observation for these
connections. Enforced hybrid-only policy, real downgrade acceptance, PQ
authentication, key lifecycle and migration for other software remain distinct
work packages. The probe does not change the encryption used by other applications.

## Primary standards and API references

[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) defines TLS 1.3 ServerHello
key shares and handshake verification. [IANA's TLS supported groups registry](https://www.iana.org/assignments/tls-parameters)
assigns 4588 to X25519MLKEM768. [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html)
defines the hybrid groups. [Python's SSL documentation](https://docs.python.org/3.14/library/ssl.html)
documents MemoryBIO, SSLObject, verification and key-log behavior.
