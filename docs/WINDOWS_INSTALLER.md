# Windows setup executable

![DVielle logo](images/dvielle-logo.png)

Version 2.4.1. This page is how to produce `DVielle-Setup-2.4.1.exe`. That file is a setup wrapper. It is not a frozen copy of the agent.

The public download on the v2.4.1 Release stays the zip. Unzip it and run `installer\Install-DVielle.bat` after Python 3.12 is installed. Use that path until a GitHub Release lists `DVielle-Setup-2.4.1.exe` by name. A GitHub Actions artifact is a build product. It expires, it is unsigned, and it is not that Release file.

## What the setup file does

1. Windows shows one Administrator prompt. That prompt is for the setup. It does not change the resident task to Highest.
2. If `py -3.12` is missing, the setup runs the official Python **3.12.10** 64-bit installer from python.org. The file is checked against `installer/python-3.12.10.pin.json` (SHA-256 and size) before it runs. An existing Python 3.12 is left in place.
3. The setup then runs `installer\install-dvielle.ps1 -RunLevel Limited`. The logon task is still `.venv\Scripts\pythonw.exe -m agent.main`. The desktop shortcut is still `pythonw.exe -m dvielle`.
4. Uninstall stays `installer\Uninstall-DVielle.bat`. The setup wrapper does not register its own uninstall entry and does not take ownership of `C:\DVILLIE`.

The wrapper has no switch for a Highest task. `-RunLevel Highest` remains the existing explicit script, and only after the install tree is locked. This setup does not call it.

The setup does not add a Defender exclusion. It is not an antivirus product. Chat stays removed.

## Why this is not a frozen .exe

PyInstaller, cx_Freeze, and Briefcase can wrap CustomTkinter, but they replace `pythonw.exe -m agent.main` with a bootloader. The resident task owner check accepts only `python.exe` or `pythonw.exe` with arguments `-m agent.main` or `-m dvielle` (`installer/common.ps1`, `Test-DvielleTaskOwner`). `scripts/verify_runtime.py` still expects a venv interpreter, including the Windows redirector case where the living image is under `sys.base_prefix`. A freeze would be a second runtime. It is follow-up work, not this installer.

The embeddable zip is also the wrong bundle. Python’s Windows docs say that package omits Tcl/Tk and pip ([Using Python on Windows, 3.12, section 4.4](https://docs.python.org/3.12/using/windows.html)). CustomTkinter needs Tcl/Tk. The full installer is the one that can supply it (`Include_tcltk`). Quiet installs of 3.12.5 and later have skipped that component unless `Include_tcltk=1` is passed ([python/cpython#123195](https://github.com/python/cpython/issues/123195)), so the pin passes it even though the documented default is 1.

Python 3.12.10 is the last 3.12 release with official Windows binaries. Later 3.12 releases are source-only under [PEP 693](https://peps.python.org/pep-0693/). The product still requires `>=3.12,<3.13`, so the pin stays on 3.12.10 rather than moving to 3.13 or 3.14. The SHA-256 `67b5635e80ea51072b87941312d00ec8927c4db9ba18938f7ad2d27b328b95fb` was checked on 2026-09-30 against the file downloaded from `https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe` (26,964,224 bytes). The same digest is in the [winget installer manifest](https://github.com/microsoft/winget-pkgs/blob/master/manifests/p/Python/Python/3/12/3.12.10/Python.Python.3.12.installer.yaml) and in the official `python:3.12.10` Windows container build args.

Silent switches follow [docs.python.org 3.12, section 4.1.3](https://docs.python.org/3.12/using/windows.html): `/quiet`, `InstallAllUsers=1`, `PrependPath=1`, launcher, pip, and `Include_tcltk=1`. `Include_test=0` matches the documented example. `AssociateFiles=0` avoids taking over `.py` associations. Some installer features can still download components; stay online when Python 3.12 is not already installed ([section 4.1.4](https://docs.python.org/3.12/using/windows.html)).

The compiler is Inno Setup 6.4.0 from `https://github.com/jrsoftware/issrc/releases/download/is-6_4_0/innosetup-6.4.0.exe`. SHA-256 `a360db165cfb1d42d195b020700181e7eaf5db45c1249a24edb51c3c33e9d659` (6,225,328 bytes), checked on 2026-09-30. The same digest is published for the official file by the Chocolatey Inno Setup 6.4.0 package. The script installs that compiler only when `ISCC.exe` is missing, and only from an Administrator shell.

## Build on a Windows PC

Windows 10 or 11, 64-bit. PowerShell 5.1. Network access to python.org and GitHub. Administrator only if Inno Setup is not already installed.

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_windows_installer.ps1
```

Output: `dist\DVielle-Setup-2.4.1.exe`. `dist\` is gitignored. The script does not upload the file.

If Inno Setup 6.4.0 or newer is already installed, the script uses `C:\Program Files (x86)\Inno Setup 6\ISCC.exe`. Pass `-Iscc` to point at another compiler. The script still refuses a Python installer whose hash or size does not match the pin.

## Build in GitHub Actions

`.github/workflows/windows-installer.yml` runs on `windows-latest` for pull requests into `main`, pushes to `main` and `cursor/**`, and manual dispatch. The `cursor/**` push is there so the compile can run before a collaborator opens the pull request. The job checks out the repo, runs the script above, and uploads `dist\DVielle-Setup-*.exe` as the artifact `DVielle-Setup`.

The workflow permission is `contents: read`. It does not create a Release and it does not attach the exe to an existing Release. The job does not run the setup on the runner, so it does not prove a resident heartbeat. That field install stays UNCHECKED. See the leftover list in [CLAIMS.md](CLAIMS.md).

## SmartScreen

The exe is unsigned. Windows can show “Windows protected your PC” for an unrecognized app. That is not a claim about malware, and it is not a claim that Defender approved the file. A signed Release is follow-up work.

## Follow-up (not in this version)

1. Publish `DVielle-Setup-2.4.1.exe` on a GitHub Release only after one Windows PC has installed it and `verify_runtime` has seen a fresh heartbeat. Until that file is listed on the Release, the zip plus Python 3.12 remains the download.
2. Authenticode signing, so SmartScreen is not the normal first-run experience.
3. A frozen `pythonw`-compatible agent, only if the task-owner check and `verify_runtime` are updated on purpose and still default to Limited. Not a silent swap to PyInstaller.
4. An ARM64 setup. This pin is the amd64 official installer.
5. An offline `/layout` of every Python component, so a PC with no network can install Tcl/Tk. Today the bundled installer may still fetch optional components.
