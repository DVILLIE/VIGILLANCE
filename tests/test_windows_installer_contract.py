"""Contracts for the setup wrapper. No compile, no download, no host mutation."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PYTHON_SHA256 = "67b5635e80ea51072b87941312d00ec8927c4db9ba18938f7ad2d27b328b95fb"
INNO_SHA256 = "a360db165cfb1d42d195b020700181e7eaf5db45c1249a24edb51c3c33e9d659"


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _json(relative: str) -> dict:
    return json.loads(_text(relative))


def test_python_pin_is_the_last_official_3_12_binary():
    pin = _json("installer/python-3.12.10.pin.json")
    assert pin["version"] == "3.12.10"
    assert pin["abi"] == "3.12"
    assert pin["arch"] == "amd64"
    assert pin["filename"] == "python-3.12.10-amd64.exe"
    assert pin["url"] == "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"
    assert pin["sha256"] == PYTHON_SHA256
    assert pin["size"] == 26964224
    assert pin["silent_args"] == [
        "/quiet",
        "InstallAllUsers=1",
        "PrependPath=1",
        "Include_launcher=1",
        "InstallLauncherAllUsers=1",
        "Include_pip=1",
        "Include_tcltk=1",
        "Include_test=0",
        "Include_doc=0",
        "Shortcuts=0",
        "AssociateFiles=0",
    ]
    blob = " ".join(pin["silent_args"])
    assert "Include_dev=0" not in blob
    assert "Highest" not in blob


def test_inno_pin_matches_the_compiler_the_build_installs():
    pin = _json("installer/inno-setup-6.4.0.pin.json")
    assert pin["version"] == "6.4.0"
    assert pin["filename"] == "innosetup-6.4.0.exe"
    assert pin["url"] == "https://github.com/jrsoftware/issrc/releases/download/is-6_4_0/innosetup-6.4.0.exe"
    assert pin["sha256"] == INNO_SHA256
    assert pin["size"] == 6225328
    assert pin["iscc"].endswith("Inno Setup 6\\ISCC.exe")
    assert "/VERYSILENT" in pin["silent_args"]


def test_bootstrap_stays_on_the_limited_installer():
    text = _text("installer/bootstrap-dvielle.ps1")
    assert "-RunLevel Limited" in text
    assert "Highest" not in text
    assert "elevate.ps1" not in text
    assert "ExclusionPath" not in text
    assert "Add-MpPreference" not in text
    assert "Get-FileHash" in text
    assert "Include_tcltk" in text
    call = text.index("& (Join-Path $PSScriptRoot 'install-dvielle.ps1')")
    assert text.index("Get-FileHash") < call


def test_setup_script_does_not_own_the_install_tree():
    text = _text("installer/DVielle.iss")
    assert "CreateAppDir=no" in text
    assert "Uninstallable=no" in text
    assert "CreateUninstallRegKey=no" in text
    assert "PrivilegesRequired=admin" in text
    assert "bootstrap-dvielle.ps1" in text
    assert '-InstallDir "C:\\DVILLIE"' in text
    assert "Highest" not in text
    assert "ExclusionPath" not in text
    assert "Add-MpPreference" not in text
    assert "PyInstaller" not in text


def test_build_script_checks_pins_and_stages_the_license():
    text = _text("scripts/build_windows_installer.ps1")
    assert "Get-FileHash" in text
    assert "python-3.12.10.pin.json" in text
    assert "inno-setup-6.4.0.pin.json" in text
    assert "'LICENSE'" in text
    assert "gh release" not in text
    assert "ExclusionPath" not in text
    assert "Highest" not in text


def test_workflow_builds_an_artifact_and_does_not_publish_a_release():
    text = _text(".github/workflows/windows-installer.yml")
    assert "runs-on: windows-latest" in text
    assert "contents: read" in text
    assert "build_windows_installer.ps1" in text
    assert "upload-artifact" in text
    assert "contents: write" not in text
    assert "softprops/action-gh-release" not in text
    assert "gh release" not in text


def test_readme_keeps_the_zip_as_the_download():
    readme = _text("README.md")
    guide = _text("docs/USER_GUIDE.md")
    notice = _text("installer/SETUP_NOTICE.txt")
    assert "DVielle-2.4.2-windows-installer.zip" in readme
    assert "Not on this Release" in readme
    assert "not a PyInstaller freeze" in readme
    assert "Chat is gone" in readme or "Not a chat assistant" in readme
    assert "Limited" in readme
    assert "Not an antivirus replacement" in readme
    assert "not on the Release" in guide
    assert "not an antivirus" in notice.lower()
    assert "Limited" in notice
    assert "DVielle-Setup-2.4.2.exe" in _text("docs/WINDOWS_INSTALLER.md")
    assert "UNCHECKED" in _text("docs/CLAIMS.md")


def test_rcedit_pin_matches_vendored_tool():
    import hashlib
    pin = _json("installer/rcedit-x64.pin.json")
    assert pin["version"] == "2.0.0"
    assert pin["filename"] == "rcedit-x64.exe"
    assert pin["sha256"].upper() == "3E7801DB1A5EDBEC91B49A24A094AAD776CB4515488EA5A4CA2289C400EADE2A"
    blob = (ROOT / "installer/tools/rcedit-x64.exe").read_bytes()
    assert len(blob) == int(pin["size"])
    assert hashlib.sha256(blob).hexdigest().upper() == pin["sha256"].upper()


def test_claims_honest_about_resident_python_vs_gui_shim():
    claims = _text("docs/CLAIMS.md")
    installer_doc = _text("docs/WINDOWS_INSTALLER.md")
    assert "DVielle.exe" in claims
    assert "pythonw.exe -m agent.main" in claims or "pythonw.exe" in claims
    assert "Branded console host" in installer_doc
    assert "resident" in installer_doc.lower()
