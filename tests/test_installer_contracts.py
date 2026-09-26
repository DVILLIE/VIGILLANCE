"""Safe PowerShell contract checks; no task, registry, firewall, or install mutations."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe")
pytestmark = pytest.mark.skipif(not POWERSHELL, reason="Windows PowerShell 5.1 required")


def run_ps(code: str, *, extra_env: dict | None = None) -> str:
    encoded = base64.b64encode(code.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ, DVIELLE_TEST_ROOT=str(ROOT), DVIELLE_TEST_PYTHON=sys.executable)
    env.update(extra_env or {})
    proc = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        env=env, text=True, capture_output=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


LOAD = """
$ErrorActionPreference = 'Stop'
. (Join-Path $env:DVIELLE_TEST_ROOT 'installer/common.ps1')
. (Join-Path $env:DVIELLE_TEST_ROOT 'scripts/hardening-common.ps1')
function Assert-True { param($Value, $Message) if (-not $Value) { throw $Message } }
"""


def test_all_powershell_scripts_parse_in_supported_host():
    run_ps(LOAD + """
foreach ($folder in @('installer', 'scripts')) {
    foreach ($file in Get-ChildItem (Join-Path $env:DVIELLE_TEST_ROOT $folder) -Filter '*.ps1' -Recurse) {
        $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors)
        if ($errors) { throw ($file.Name + ': ' + ($errors -join ', ')) }
    }
}
""")


def test_native_failure_stops_following_steps():
    run_ps(LOAD + """
$nextStep = $false
$failed = $false
try {
    Invoke-DvielleNative $env:DVIELLE_TEST_PYTHON @('-c', 'raise SystemExit(7)')
    $nextStep = $true
} catch { $failed = $_.Exception.Message -match 'exit code 7' }
Assert-True ($failed -and -not $nextStep) 'Native failure was not propagated.'
Invoke-DvielleNative $env:DVIELLE_TEST_PYTHON @('-c', 'raise SystemExit(0)')
""")


def test_legacy_global_python_blocks_upgrade_without_termination():
    run_ps(LOAD + r"""
function Get-CimInstance {
    param($ClassName, $ErrorAction)
    [pscustomobject]@{ Name='pythonw.exe'; ProcessId=54321; ExecutablePath='C:\Python312\pythonw.exe'; CommandLine='pythonw.exe -m agent.main' }
}
function Invoke-DvielleNative { throw 'Must not request stop before identifying legacy processes' }
function Get-Process { throw 'Must not terminate or signal an ambiguous process' }
$rejected = $false
try { Stop-DvielleOwnedRuntime 'C:\DVILLIE' } catch { $rejected = $_.Exception.Message -match 'Legacy or external DVielle.*54321' }
Assert-True $rejected 'Upgrade failed to stop before legacy collector interference.'
""")


def test_root_and_task_ownership_are_bounded(tmp_path):
    run_ps(LOAD + r"""
foreach ($unsafe in @('C:\', 'C:', 'relative\install', $env:SystemRoot, $env:USERPROFILE)) {
    $rejected = $false
    try { $null = Resolve-DvielleRoot $unsafe } catch { $rejected = $true }
    Assert-True $rejected ('Protected root accepted: ' + $unsafe)
}
$root = Resolve-DvielleRoot $env:DVIELLE_TEST_DIRECTORY
$action = [pscustomobject]@{ WorkingDirectory = $root; Execute = (Join-Path $root '.venv\Scripts\pythonw.exe'); Arguments = '-m agent.main' }
$task = [pscustomobject]@{ Actions = @($action) }
Assert-True (Test-DvielleTaskOwner $task $root) 'Expected owned task was rejected.'
$action.Arguments = '-m agent.main --config-dir C:\Other'
Assert-True (-not (Test-DvielleTaskOwner $task $root)) 'Task with another configuration was accepted.'
$action.Arguments = '-m agent.main'
$action.WorkingDirectory = $root + '-other'
Assert-True (-not (Test-DvielleTaskOwner $task $root)) 'Neighbor installation task was accepted.'
""", extra_env={"DVIELLE_TEST_DIRECTORY": str(tmp_path)})


def test_install_tree_rejects_escape_and_nested_junction(tmp_path):
    run_ps(LOAD + r"""
$root = Resolve-DvielleRoot $env:DVIELLE_TEST_DIRECTORY
$safe = Join-Path $root 'safe'
$outside = Join-Path $root 'outside'
$null = New-Item -ItemType Directory -Path $safe, $outside
$link = Join-Path $safe 'redirect'
Assert-DvielleTreeNoReparse $root $safe
$rejected = $false
try { Assert-DvielleTreeNoReparse $safe $outside } catch { $rejected = $_.Exception.Message -match 'outside' }
Assert-True $rejected 'A sibling target escaped its allowed root.'
$null = New-Item -ItemType Junction -Path $link -Target $outside
try {
    $rejected = $false
    try { Assert-DvielleTreeNoReparse $root $safe } catch { $rejected = $_.Exception.Message -match 'Reparse-point' }
    Assert-True $rejected 'A nested junction was accepted for recursive filesystem work.'
} finally {
    # Delete only the link itself, never its destination or a recursive target.
    [IO.Directory]::Delete($link)
}
""", extra_env={"DVIELLE_TEST_DIRECTORY": str(tmp_path)})


def test_foreign_task_prevents_all_trigger_changes(tmp_path):
    run_ps(LOAD + r"""
$root = Resolve-DvielleRoot $env:DVIELLE_TEST_DIRECTORY
$script:Disabled = @()
function Get-ScheduledTask {
    param($TaskName, $TaskPath, $ErrorAction)
    $working = $root
    if ($TaskName -eq 'DVielleGUI') { $working += '-foreign' }
    return [pscustomobject]@{ Actions = @([pscustomobject]@{
        WorkingDirectory = $working; Execute = (Join-Path $root '.venv\Scripts\pythonw.exe'); Arguments = '-m agent.main'
    }) }
}
function Disable-ScheduledTask { param($TaskName, $TaskPath, $ErrorAction) $script:Disabled += $TaskName }
$rejected = $false
try { Disable-DvielleOwnedTasks $root } catch { $rejected = $_.Exception.Message -match 'another installation' }
Assert-True ($rejected -and $script:Disabled.Count -eq 0) 'Owned triggers changed before a foreign task was rejected.'
""", extra_env={"DVIELLE_TEST_DIRECTORY": str(tmp_path)})


def test_update_domain_boundaries_and_managed_hosts_preserve_user_entries():
    run_ps(LOAD + """
foreach ($domain in @('settings-win.data.microsoft.com', 'child.windowsupdate.com', 'DOWNLOAD.MICROSOFT.COM.')) {
    Assert-True (Test-IsUpdateSafe $domain) ('Required endpoint was not excluded: ' + $domain)
}
foreach ($domain in @('settings-win.data.microsoft.com.evil.test', 'notwindowsupdate.com')) {
    Assert-True (-not (Test-IsUpdateSafe $domain)) ('Suffix lookalike accepted: ' + $domain)
}
$before = "127.0.0.1 localhost`r`n# user entry`r`n10.0.0.8 fileserver`r`n# DVielle telemetry block`r`n0.0.0.0 old.example.com`r`n# another user entry`r`n10.0.0.9 printer`r`n"
$after = Get-ManagedHostsContent $before @('new.example.com', 'new.example.com')
Assert-True ($after.Contains('10.0.0.8 fileserver') -and $after.Contains('10.0.0.9 printer')) 'User hosts content was lost.'
Assert-True (-not $after.Contains('old.example.com')) 'Old managed entry remained.'
Assert-True (([regex]::Matches($after, 'new.example.com')).Count -eq 1) 'Duplicate managed entries written.'
Assert-True ((Get-ManagedHostsContent $after @('new.example.com')) -ceq $after) 'Managed hosts update is not idempotent.'
""")


REGISTRY_FIXTURE = r"""
# In-memory registry stand-ins: only the backup file is written in pytest's temporary directory.
function Assert-HardeningAdmin { }
$script:Mutations = 0
$script:KeyCreations = 0
function Get-HardeningRegistryState { param($Path, $Name) return $script:Current }
function Test-Path { param($LiteralPath) return $true }
function New-Item { param($Path, [switch]$Force, $ErrorAction) $script:Mutations++; $script:KeyCreations++ }
function New-ItemProperty {
    param($LiteralPath, $Name, $Value, $PropertyType, [switch]$Force)
    $script:Mutations++
    $script:Current = [pscustomobject]@{ Exists = $true; Kind = $PropertyType; Value = $Value }
}
function Remove-ItemProperty {
    param($LiteralPath, $Name, $ErrorAction)
    $script:Mutations++
    $script:Current = [pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }
}
$entry = [pscustomobject]@{
    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'
    KeyExisted = $true; Existed = $true; OldKind = 'String'; OldValue = 'original'; NewValue = 1
}
$backup = [pscustomobject]@{
    Schema = 1; Machine = $env:COMPUTERNAME
    UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    OperationId = '0123456789abcdef0123456789abcdef'
    Hosts = $null; Registry = @($entry); FirewallRules = @(); Restored = $false
}
"""


@pytest.mark.parametrize("current", [
    "[pscustomobject]@{ Exists = $false; Kind = $null; Value = $null }",
    "[pscustomobject]@{ Exists = $true; Kind = 'String'; Value = '1' }",
    "[pscustomobject]@{ Exists = $true; Kind = 'DWord'; Value = 2 }",
])
def test_restore_rejects_later_registry_deletion_type_change_or_edit(tmp_path, current):
    run_ps(LOAD + REGISTRY_FIXTURE + f"$script:Current = {current}\n" + """
Save-HardeningBackup $backup $env:DVIELLE_TEST_BACKUP
$rejected = $false
try { Restore-HardeningBackup $env:DVIELLE_TEST_BACKUP } catch { $rejected = $_.Exception.Message -match 'Registry changed' }
Assert-True ($rejected -and $script:Mutations -eq 0) 'Restore overwrote a later registry change.'
""", extra_env={"DVIELLE_TEST_BACKUP": str(tmp_path / "backup.clixml")})


@pytest.mark.parametrize("original_exists", [True, False])
def test_restore_recovers_original_kind_or_absence_and_marks_verified_backup(tmp_path, original_exists):
    exists = "$true" if original_exists else "$false"
    run_ps(LOAD + REGISTRY_FIXTURE + f"$entry.Existed = {exists}\n" + """
$script:Current = [pscustomobject]@{ Exists = $true; Kind = 'DWord'; Value = 1 }
Save-HardeningBackup $backup $env:DVIELLE_TEST_BACKUP
Restore-HardeningBackup $env:DVIELLE_TEST_BACKUP
Assert-True (Test-HardeningRegistryState $script:Current $entry.Existed $entry.OldKind $entry.OldValue) 'Original registry state not restored.'
Assert-True ((Import-Clixml -LiteralPath $env:DVIELLE_TEST_BACKUP).Restored) 'Restore verification was not persisted.'
Assert-True ($script:KeyCreations -eq 0) 'Restore recreated an existing registry key and endangered unrelated values.'
""", extra_env={"DVIELLE_TEST_BACKUP": str(tmp_path / "backup.clixml")})


def test_apply_changes_one_registry_value_without_recreating_existing_key(tmp_path):
    run_ps(LOAD + REGISTRY_FIXTURE + r"""
$script:Current = [pscustomobject]@{ Exists = $true; Kind = 'DWord'; Value = 3 }
$script:RegistryKey = New-Object PSObject
$script:RegistryKey | Add-Member ScriptMethod GetValueNames { @('AllowTelemetry', 'UnrelatedPolicy') }
$script:RegistryKey | Add-Member ScriptMethod GetValue { param($Name, $Default, $Options) return 3 }
$script:RegistryKey | Add-Member ScriptMethod GetValueKind { param($Name) return [Microsoft.Win32.RegistryValueKind]::DWord }
function Get-Item { param($LiteralPath) return $script:RegistryKey }
$backup.Registry = @()
Set-HardeningRegistryValue $backup $env:DVIELLE_TEST_BACKUP $entry.Path $entry.Name 1
Assert-True ($script:KeyCreations -eq 0 -and $script:Mutations -eq 1) 'Apply recreated an existing registry key instead of changing only one value.'
Assert-True ($backup.Registry.Count -eq 1 -and $backup.Registry[0].OldValue -eq 3) 'Original target value was not journaled.'
Assert-True (Test-HardeningRegistryState $script:Current $true 'DWord' 1) 'Requested value was not verified.'
""", extra_env={"DVIELLE_TEST_BACKUP": str(tmp_path / "backup.clixml")})
