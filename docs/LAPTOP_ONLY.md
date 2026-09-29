# Install and run DVielle on Windows

Updated 2026-09-13 for DVielle 1.6.0. These commands apply to the Windows laptop where monitoring will run.

## Install or update

1. Install the free Python 3.12 Windows distribution from [python.org](https://www.python.org/downloads/windows/), including Tcl/Tk and the Python launcher.
2. Open the project folder and run `installer\Install-DVielle.bat`. Approve its Windows elevation prompt. The default destination is `C:\DVILLIE`.
3. The installer uses `C:\DVILLIE\.venv`, syncs `[project].dependencies` (including `cryptography`) with `pip install --upgrade --upgrade-strategy only-if-needed -e ".[windows,chat]"`, checks imports, requests failure auditing, registers one resident task, starts it and verifies a fresh heartbeat from its process. A file copy onto an existing install does not refresh `.venv` by itself. From that install root, run the same pip command, then `python -m pip check` and `scripts\smoke_test.py`, before starting the resident. `smoke_test.py` imports `agent.update.tuf`, which needs `cryptography`. The install stops before the task is enabled if that import fails.

Existing configuration and data are preserved when copying from another checkout. Existing DVielle startup triggers are disabled before the old runtime is asked to stop gracefully. If its windows remain open, exit DVielle from its tray menu and retry. An older installation without the shared runtime protocol may also need to be closed manually. No arbitrary Python process is force-killed.

Installation stops on a failed prerequisite or native command. A failed update may leave startup disabled and partially updated application files; preserve configuration and retry from a complete checkout after resolving the reported error. This installer does not provide an atomic package rollback.

For a custom location, invoke `installer\install-dvielle.ps1 -InstallDir 'C:\Apps\DVielle'` from an Administrator PowerShell. Install into a dedicated local directory; drive roots, shared user/Windows directories and reparse-point paths are rejected.

## Resident monitor and console

The `DVielle` scheduled task runs `.venv\Scripts\pythonw.exe -m agent.main` at logon for the installing Windows account. It uses an unlimited execution time, allows battery operation, suppresses duplicate task instances and requests three restarts after failure. Registration is read back before activation. This is an interactive-account task; it does not provide pre-logon or logged-out monitoring. Microsoft's [ExecutionTimeLimit documentation](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-executiontimelimit) explains why the default 72-hour limit must be changed for a resident process.

Open the desktop shortcut or `installer\Launch-DVielle.bat` for the console. It attaches to the resident owner; it can own the runtime when no resident instance is running. Opening the console does not create a second set of collectors. `Launch-DVielle-Debug.bat` uses the same environment and preserves its exit code.

```powershell
# Read-only import and configuration checks; no host collection.
.\.venv\Scripts\python.exe scripts\smoke_test.py
# Verify an existing resident process and its recent heartbeat.
.\.venv\Scripts\python.exe scripts\verify_runtime.py --config-dir config --timeout 10
# Request a graceful stop of the runtime that owns this configuration's data directory.
.\.venv\Scripts\python.exe -m agent.main --stop --config-dir config
```

A verified heartbeat establishes that the resident process is alive. Consult collector timestamps and errors in the console for coverage; a heartbeat alone does not prove every provider succeeded.

## Optional hardening and removal

Hardening scripts preview their scope by default. Read [telemetry limits and restoration](TELEMETRY_AND_HOME.md) before applying them. They do not run during installation or normal collection.

Run `installer\Uninstall-DVielle.bat` to remove owned startup registrations and shortcuts. It requests graceful shutdown first. Files are retained unless you type `DELETE` for the validated installation directory. To retain files without the deletion prompt, run `installer\uninstall-dvielle.ps1 -KeepData` as Administrator. Restore optional Windows hardening from its saved backup before deleting the installation if you want those settings reverted. Custom data directories outside the installation are retained.
