# D'Vielle Local Report Signing and Key Lifecycle Runbook

## Purpose and verified scope

An ML-DSA-65 detached signature authenticates exact exported report bytes to a retained signer fingerprint. It does not prove that a finding is correct, authenticate a public software publisher, authorize operating-system changes, or turn classical network certificates into post-quantum certificates. Real installed rotation, retirement, revocation and legacy-key compatibility were checked in this release increment.

The active seed and retired/revoked fingerprint registry share one Windows user-DPAPI encrypted file. Atomic replacement avoids separate seed/registry updates. The first file handle restricts access to the current user, Administrators and SYSTEM. Windows DPAPI binds decryption to the user context. No USB key, Microsoft account token or cloud account is needed for this local function.

## Create and retain a signer

1. Open **Advanced ethical hacking**, run an assessment, enable **Sign exports locally with ML-DSA-65**, and export the redacted report.
2. Keep the report and its `.sig.json` sidecar together. The sidecar contains public material and the signature, not the private seed.
3. Open **Quantum readiness → Local report signer → Check signer**. Retain the displayed fingerprint in an independently controlled record before accepting reports from that signer.
4. The signer is not generated merely by checking its status. A missing signer is reported honestly until the first signed export.

## Verify a report

1. Choose **Verify signed report** and select the exported JSON report. The matching sidecar must be beside it.
2. Local verification checks exact bytes, ML-DSA signature, signer identity and lifecycle status against the existing local registry.
3. An active or normally retired signer may verify. An unknown or revoked signer is rejected. A modified report, substituted public key, invalid signature or unreadable sidecar is not reported as verified.
4. Independent verification outside this installation must use a separately trusted fingerprint and the verifier's own current revocation policy; importing a sidecar does not establish trust.

## Planned rotation

1. Select **Check signer** and confirm that the current fingerprint matches your independently retained record.
2. Select **Rotate signer** and read the confirmation. The update compares the current fingerprint again before replacing anything.
3. Retain the new fingerprint independently. Subsequent signed exports use the new key. Existing reports from the previous signer remain locally verifiable with a **retired** status.
4. The old seed is removed from the active encrypted record. This is not a claim that storage remnants were physically erased.

## Suspected compromise

1. Select **Revoke & replace** only after reviewing the consequence: old reports from that signer will fail local lifecycle verification.
2. Confirm the operation, retain the new fingerprint, and explicitly inform any external verifier through an already trusted channel. This application does not send messages or silently update another party's trust.
3. Re-export/re-sign an assessment only after reviewing its actual evidence. Signing old bytes under a new key does not repair compromised or incorrect evidence.

## Failure and recovery

- A fingerprint mismatch stops rotation without changing the active record.
- A write or replacement failure reports no success; recheck the current signer before retrying. Secure temporary ciphertext is cleaned up after a failed write.
- Corrupt encrypted data, an inaccessible Windows profile or a DPAPI failure is not bypassed. Preserve the encrypted file and investigate the profile/storage problem. Never replace it silently or print private seed bytes.
- A registry with 256 retired entries refuses another rotation rather than discarding historical revocations. Review retention/migration deliberately.
- Any encrypted backup remains private and must be restored only as a reviewed recovery operation; restoring an older record can also restore outdated revocation state. Do not upload private key files to GitHub or include them in a public release.

## Operator CLI

Use the verified installed interpreter and the actual assessment key directory:

```powershell
& 'C:\Program Files\DVielle\.venv\Scripts\python.exe' -I -B -m agent.assessment.signatures status --key-directory '<actual assessment directory>\security'
& 'C:\Program Files\DVielle\.venv\Scripts\python.exe' -I -B -m agent.assessment.signatures verify --key-directory '<actual assessment directory>\security' --report '<report.json>' --signature '<report.json.sig.json>'
```

Rotation additionally requires `rotate --expected-fingerprint <independently retained current fingerprint>`; add `--revoke-previous` only for revocation. The key directory must be the existing operator's directory, not a newly invented trust store. Commands run under that operator's Windows identity.

## Acceptance evidence and primary references

`ACTUAL_INSTALLED_KEY_LIFECYCLE_ACCEPTANCE_2026-10-11.json` records real installed cryptographic retirement/revocation with temporary acceptance keys. `ACTUAL_INSTALLED_LIFECYCLE_ASSESSMENT_ACCEPTANCE_2026-10-11.json` records a real installed assessment with its existing operator signer unchanged. `ACTUAL_INSTALLED_LIFECYCLE_GUI_SCALING_2026-10-11.json` records actual keyboard/scaling observations. These do not substitute for a human screen-reader review.

Implementation references: [Microsoft CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [cryptography ML-DSA](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/mldsa/), [GitHub artifact-attestation verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations). GitHub's workflow attestations authenticate CI result provenance separately from these local report signatures.
