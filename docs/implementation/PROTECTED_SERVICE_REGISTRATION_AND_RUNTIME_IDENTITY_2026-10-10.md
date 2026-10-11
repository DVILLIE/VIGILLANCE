# D’Vielle Protected Service Registration and Runtime Identity

## Research conclusions and engineering decisions

Microsoft reserves service creation for Administrator processes and warns that
granting service configuration changes to untrusted users can execute code as
LocalSystem. The executable path must be quoted. Accordingly, registration uses
a fixed service identity, an exact quoted interpreter command, isolated Python,
disabled bytecode writes, LocalSystem and manual startup. It never replaces an
existing same-name service or automatically starts the helper.

The Update Framework separates a trusted root from candidate metadata. A hash
provided by the same candidate is not publisher authentication. This work adds
an explicit operator-approved runtime digest; it does not invent publisher
identity, automatically enroll a signing key or claim TUF certification. Existing
TUF verification and publisher release management remain separate capabilities.

## Implemented components

`agent/privilege/release_identity.py` inventories the actual application packages,
virtual environment Lib/Scripts and base Python Lib/DLLs/core executables and
DLLs. Bytecode is included because Python may read it even when -B disables
writes. Records contain file size and SHA256. Verification refuses changed,
missing or additional files, reparse inputs, traversal, duplicate paths/JSON
fields, unsupported roots and oversized inventories. Production checks also
require protected owners, writers and ancestors.

`scripts/record_runtime_manifest.py` records an actual candidate fingerprint
with exclusive output creation. Its output explicitly grants no authorization
and asserts no publisher authentication.

`installer/configure-protection-state.ps1` requires an Administrator token and
the exact trusted installed source/runtime. Windows must resolve the supplied
SID as a user account. It creates private common-data directories with
SYSTEM/Administrators permissions at creation, refuses existing mutable paths,
and writes the versioned user binding without replacing existing bindings.
It does not register a service, start protection or change firewall rules.

`agent/privilege/service_install.py` implements explicit register, start and
remove commands. Registration verifies the independently approved manifest
digest and protected runtime, writes protected identity records and creates a
stopped demand-start helper. Service ownership and DACL readback are checked;
only SYSTEM/Administrators may change or control it. Other authenticated users
receive query/read rights. A failed registration does not silently start or
delete the service or discard recovery evidence; its state requires review.

Start verifies the complete runtime and exact SCM executable, account, service
type, owner and DACL. It reports a start request, not a successful protection
claim. Remove requires the exact stopped helper and preserves grants, journals,
identity records and firewall rules. There is no automatic force-stop or blind
rollback. Removal with changed runtime identity requires independent recovery.

The helper verifies its protected approved runtime identity before dispatching
requests. Readiness reports identity failures distinctly from valid installation
configuration. Uninstall refuses to delete application code while SCM still
references the privileged helper; service enumeration failure is not absence.

## Actual verification

The full suite completed with **649 passed, eight skipped and nine warnings in
99.88 seconds**. All eight skips reported unavailable Tk support. They are not
passes or visual acceptance. Existing Pillow warnings are retained. The full
log is `PROTECTED_REGISTRATION_TEST_RESULTS_2026-10-10.txt`.

After the final small refinements, 23 focused runtime-identity/native-dispatch/
readiness tests and 15 installer tests passed. These tests include real filesystem
tampering and actual Windows security-descriptor decoding, with no SCM creation,
service elevation or firewall mutation. The standard-user refusal is an actual
token-based check. Descriptor fixtures are contract evidence, not installed
service evidence. Changed-source whitespace checks passed.

An actual runtime fingerprint was recorded in
`RUNTIME_IDENTITY_CANDIDATE_2026-10-10.json` with SHA256
`9fd2130a9e4947ccd923568049ee898f565d555af74b718b13a294d70a82519e`.
This is a development snapshot, not a publisher signature or authorization.
An actual read-only comparison matched all **11,187 inventoried files** to that
digest and returned `runtime_digest_verified_unprotected` with publisher
authentication false. This validates snapshot consistency only; protected
activation and independent operator approval were not performed.

Fresh read-only machine observation at `2026-10-10T11:36:35.334547+00:00`
found a non-elevated session, rejected source/interpreter protection checks,
helper absence (Windows error 1060), missing protected user configuration and
no mutations. These facts prevent activation from this checkout.

## Step-by-step activation journey

1. Complete an independently verified release and protected bootstrap stage.
   Review its source, Python provenance and the 17-wheel offline bundle. The
   current unsigned mutable candidate is not that trusted stage.
2. Use the legitimate Windows Administrator installation from that verified
   stage, supplying its protected offline bundle. The resident remains Limited.
3. In the trusted installation, run `configure-protection-state.ps1 -UserSid`
   with the exact intended Windows user SID. Existing bindings require migration,
   not replacement. No USB authentication key is required by these commands.
4. Record an installed runtime manifest under `-B`, review its inputs and approve
   its exact digest independently. Copy it into protected state through trusted
   administrative tooling; do not self-approve a digest taken from untrusted input.
5. From the trusted installed isolated interpreter under an Administrator token,
   run `-m agent.privilege.service_install register --manifest <protected-file>
   --approved-sha256 <reviewed-digest>`. Confirm stopped service readback.
6. Run the explicit `service_install start` command. Then independently verify
   SCM running state, actual SYSTEM pipe peer identity, intended user binding,
   denial for other users/remote clients and lost-response recovery.
7. Issue a bounded approved grant and measure IPv4/IPv6 traffic containment and
   conditional restoration in an owned test environment. Include TCP, UDP/QUIC,
   existing sessions, VPN/proxy and external policy changes. Configuration readback
   alone does not pass these acceptance checks.
8. Complete resource/accessibility/edition/pilot acceptance before distribution.
   Use reviewed signing/root rotation and update/uninstall recovery policies.

This work completes source paths for identity verification, private binding and
controlled registration. Protected bootstrap/release distribution, actual
Administrator installation, positive deployed peer/enforcement evidence and
the wider twenty-step acceptance plan remain open. Runtime hashing is performed
at activation/startup; it is not continuous memory/process attestation and its
performance must be measured before a pilot.

## Verified primary sources

- [Microsoft service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Microsoft CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)
- [Pywin32 service utility source](https://github.com/mhammond/pywin32/blob/main/win32/Lib/win32serviceutil.py)
- [TUF roles and metadata](https://theupdateframework.io/docs/metadata/)
- [Microsoft Authenticode inspection](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)

Research informs these choices; it does not certify an unsigned build, an
uninstalled service or quantum-resistant protocol negotiation.
