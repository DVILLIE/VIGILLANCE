# D’Vielle Activation Attempt and Python 3.14 Migration Candidate

Historical checkpoint: the cancellation and uninstalled state below were subsequently superseded by [actual protected deployment and live helper verification](PYTHON314_PROTECTED_DEPLOYMENT_2026-10-10.md).

## Outcome

The authorized Administrator installation was attempted using the actual
official Python Software Foundation installer. Windows returned **“The operation
was canceled by the user.”** The target interpreter remains absent. No protected
D’Vielle runtime or privileged helper was activated. The UAC request was not
repeated after cancellation.

## Research and verified artifacts

The development interpreter is Python 3.12.10 in user-writable storage. Official
[Python 3.12.15 release guidance](https://www.python.org/downloads/release/python-31215/)
confirms that later 3.12 security releases are source-only; 3.12.10 was the final
release with Windows binary installers. Installing that older runtime as SYSTEM
would not resolve the current runtime-update requirement.

The actual [Python 3.14.8 Windows installer](https://www.python.org/downloads/release/python-3148/)
was downloaded from Python.org. Its SHA256 matches the release page:
`759be887b96e736a3ca886daf8d575f18fcae1a09efab6902f42d59e8999f8ef`.
Its actual size is 33,387,464 bytes. Windows reported a Valid Authenticode
signature issued to Python Software Foundation. During launch, a read-only
file lease blocked writes/renames through the normal RunAs request. The proposed
dedicated target is `C:\Program Files\DVielleRuntime\Python314`; PATH, file
associations and the global Python launcher were not requested to change.

Seventeen Python 3.14-targeted dependency wheels were downloaded, individually
verified against PyPI metadata and checked for a complete hashed offline
dependency closure. They remain candidates, not an installed 3.14 environment.

The final local activation archive is
`dist/DVielle-activation-python314-20261010-r3.zip`: **269 files**, CRC checked,
with actual SHA256
`a8d70a983f184bc88ce59f4541a4c4993a909327caf62984b7e41ab9e7c00179`.
Source folders and offline wheels are included; environment secrets, live data,
Git state and bytecode caches are excluded. A local archive hash is not a
publisher signature or globally trusted distribution channel.

## Implementation and checks

- The project/smoke check accepts the existing 3.12 development runtime and a
  3.14 migration candidate. 3.13 is excluded because it has not been validated.
- SYSTEM helper activation now refuses runtimes older than 3.14.8 or outside
  the 3.14 series. Readiness explicitly reports the runtime-version hold.
- The installer accepts an explicit protected 3.14.8+ interpreter path.
- `scripts/install_verified_python314.ps1` provides a reusable, hash/signature
  checked launch of the official installer through normal Windows approval.
- `scripts/stage_activation_payload.ps1` snapshots its bootstrap into an
  encoded command to the system PowerShell executable, rather than elevating
  a mutable script filename. It checks the independently approved archive
  digest before creating a new protected directory. Extraction refuses traversal,
  Windows device/alternate-stream names, duplicates, overwrites and excessive
  expansion. No extracted payload code is executed by staging.

The complete regression checkpoint ran on **Python 3.12.10** and completed with
**658 passed, no skips and nine existing Pillow warnings in 91.82 seconds**.
Sixteen installer tests passed after the final launcher addition, including
parsing the elevated bootstrap body without running it. Eighteen focused
identity/readiness tests passed after the final version-reporting change.
These results do not establish Python 3.14 compatibility, successful elevated
staging, actual SCM registration or traffic enforcement.

Fresh readiness at `2026-10-10T11:58:10.585757+00:00` reports a non-elevated
session, Python 3.12.10, failed code/runtime protection checks, Windows service
error 1060 and missing protected binding. Its read-only mutations list is empty.
Local downloads and candidate file creation are separately recorded above.

## Remaining activation sequence

1. Approve the normal Windows prompt when the verified runtime launcher is
   explicitly retried. Check the installed runtime's ownership/ACLs and version.
2. Install the pinned offline dependencies into a separate 3.14 environment;
   run actual 3.14 smoke/regression/GUI/native tests and repair any incompatibility.
3. Stage the reviewed archive with its exact approved SHA256 using the protected
   staging launcher. Its expected digest must come from independent review,
   not automatic acceptance of an untrusted manifest.
4. Install from the resulting protected stage with the explicit interpreter and
   protected dependency bundle. Configure the exact intended Windows user SID.
5. Record and approve the installed runtime baseline, register the stopped
   helper, request startup, then prove actual SYSTEM peer identity and scoped
   IPv4/IPv6 enforcement/restoration before claiming protection.

The launcher follows [Microsoft Start-Process RunAs guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process).
Directory protection is applied at creation, consistent with
[Microsoft CreateDirectory security semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw).
Windows administrator consent remains a real prerequisite; no permission bypass
or USB-key requirement was added.
