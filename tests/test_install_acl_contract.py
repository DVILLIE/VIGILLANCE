"""Linux-side contract for Highest-after-ACL and block-ip verification.

Windows PowerShell execution is covered by tests/test_installer_contracts.py
and skips when powershell.exe is absent.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_no_defender_exclusion_path():
    for relative in ("installer/install-dvielle.ps1", "installer/common.ps1", "installer/elevate.ps1", "scripts/install.ps1"):
        text = _text(relative)
        assert "ExclusionPath" not in text
        assert "Add-MpPreference" not in text


def test_limited_is_the_default_and_highest_is_after_acl_lockdown():
    install = _text("installer/install-dvielle.ps1")
    assert "[string]$RunLevel = 'Limited'" in install
    assert "Protect-DvielleInstallForElevation" in install
    assert install.index("Protect-DvielleInstallForElevation") < install.index("Register-ScheduledTask")
    assert "Refusing to create or enable a Highest scheduled task" in install
    assert "Refusing to enable a Highest scheduled task" in install
    assert install.index("Test-DvielleElevatedTree") < install.index("Enable-ScheduledTask")
    refuse_enable = install.index("Refusing to enable a Highest scheduled task")
    assert install.rfind("Unregister-ScheduledTask", 0, refuse_enable) > install.index("Register-ScheduledTask")
    common = _text("installer/common.ps1")
    for sid in ("S-1-5-32-544", "S-1-5-18", "S-1-5-11", "S-1-5-32-545"):
        assert sid in common
    assert "ReadAndExecute" in common
    assert "function Protect-DvielleInstallForElevation" in common
    assert "function Test-DvielleAclDeniesUserWrite" in common
    assert "TASK_RUNLEVEL_HIGHEST" in install or "TASK_RUNLEVEL_HIGHEST" in common


def test_install_resyncs_declared_dependencies_before_the_resident_starts():
    install = _text("installer/install-dvielle.ps1")
    pyproject = _text("pyproject.toml")
    smoke = _text("scripts/smoke_test.py")
    assert "cryptography>=41" in pyproject
    assert "'--upgrade'" in install
    assert "'only-if-needed'" in install
    assert "'.[windows,chat]'" in install
    pip_at = install.index("'-m', 'pip', 'install'")
    smoke_at = install.index("scripts\\smoke_test.py')")
    register_at = install.index("Register-ScheduledTask")
    assert pip_at < smoke_at < register_at
    assert "agent.update.tuf" in smoke
    assert "[string]$RunLevel = 'Limited'" in install
    assert "ExclusionPath" not in install


def test_block_ip_does_not_treat_a_name_match_as_protection():
    script = _text("scripts/block-ip.ps1")
    assert "Test-DvielleBlockCoversAddress" in script
    assert "Rule already exists" not in script
    assert "Not protected" in script
    assert script.index("Test-DvielleBlockCoversAddress") < script.index("Verified existing inbound block")
    assert "does not block" in script
    assert "DualGate" in script or "not a DVielle product" in script.lower() or "Not a DVielle product" in script
