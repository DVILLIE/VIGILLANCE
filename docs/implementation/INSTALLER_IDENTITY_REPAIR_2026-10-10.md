# D’Vielle Installer Identity and Ownership Repair

## Verified problem and resolution

The installer registered `D'Vielle` while its verification, activation and
failure cleanup used `DVielle`. Upgrade and uninstall also used `DVielle`.
This could leave the newly registered resident task outside the expected
lifecycle. Registration now uses the stable machine identity `DVielle`;
the visible description remains `D'Vielle resident monitor`.

The ownership predicate previously accepted any executable named python.exe
or pythonw.exe when the working directory and module arguments matched.
It now requires an absolute executable path equal to the installation's
`.venv\Scripts\python.exe` or `.venv\Scripts\pythonw.exe`. External and
relative executable paths cannot authorize task disable/removal.

## Verification and evidence boundary

Fourteen installer contract tests passed in the actual Windows PowerShell
host. These include parsing every PowerShell script, inspecting the installer
AST for consistent task identities, and checking ownership against neighboring,
external and relative runtime paths. The checks do not install or modify tasks.
The targeted Git whitespace check passed for the three changed source files.
The subsequent full suite completed with 640 passed, one skipped and nine
existing Pillow deprecation warnings in 87.36 seconds. Its actual final summary
is saved in `INSTALLER_REGRESSION_RESULTS_2026-10-10.txt`; the skipped test is
not counted as a pass.

No scheduled task was registered, started, disabled or removed in this repair.
The previously saved installed-readiness observation remains historical:
the privileged helper was not installed and activation prerequisites were unmet.
This repair does not establish a deployed service or packet enforcement.

## Research and remaining deployment work

Microsoft documents TaskName as the scheduled task's identity and Description
as its descriptive text: [Register-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask).

The installer still contains online editable dependency installation. The setup
builder explicitly refuses to run pending protected bootstrap/compiler staging.
These holds have not been removed. The next release work must produce pinned,
complete dependency requirements, verified offline artifacts, an independently
trusted release identity, and protected installation before service activation.
Pip's [secure installation guidance](https://pip.pypa.io/en/stable/topics/secure-installs/)
requires complete hashes and pinned requirements for hash-checking mode;
hash consistency alone is not publisher authentication.

The entire implementation plan remains open until deployment, live enforcement,
recovery, interoperability, performance and pilot acceptance are actually verified.
