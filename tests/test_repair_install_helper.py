"""Regression/unit proof only: no installer or Windows security mutation."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import socket
import subprocess

import pytest

from agent.policy.dual import _mutate_depth
from agent.privilege.broker import submit_restrict_network
from agent.privilege.contract import validate_restrict_params
from agent.privilege.helper import LoopbackHelper, dispatch, main
from agent.privilege.pipe import PIPE_CLIENT_RIGHTS, describe_pipe


def _envelope(program: Path) -> dict:
    return {"v": 1, "op": "restrict_network", "token": "ab" * 32,
            "params": {"program": str(program), "profile": "Public"}}


def test_token_alone_never_authorizes_production_or_elevated_harness(tmp_path, monkeypatch):
    program = tmp_path / "application.exe"
    program.write_bytes(b"unit fixture only")
    calls = []
    runner = lambda script: calls.append(script) or ("", False)
    request = _envelope(program)
    monkeypatch.setattr("agent.privilege.helper._is_elevated", lambda: False)
    assert dispatch(request, runner=runner, expected_token=request["token"])["code"] == "service_unavailable"
    with pytest.raises(RuntimeError, match="test harness"):
        LoopbackHelper(runner)
    monkeypatch.setattr("agent.privilege.helper._is_elevated", lambda: True)
    assert dispatch(request, runner=runner, expected_token=request["token"], test_harness=True)["code"] == "service_unavailable"
    with pytest.raises(RuntimeError, match="test harness"):
        LoopbackHelper(runner, test_harness=True)
    assert calls == []
    assert main(["--endpoint-file", str(tmp_path / "endpoint.json")]) == 2
    assert not (tmp_path / "endpoint.json").exists()


@pytest.mark.parametrize("profile", [{}, [], 1, None, True])
def test_unhashable_or_wrong_type_profiles_are_refused(tmp_path, profile):
    program = tmp_path / "app.exe"
    program.write_bytes(b"fixture")
    assert validate_restrict_params({"program": str(program), "profile": profile})[0] is None


def test_bad_request_does_not_kill_harness_and_adapter_failure_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.privilege.helper._is_elevated", lambda: False)
    program = tmp_path / "app.exe"
    program.write_bytes(b"fixture")
    calls = []

    def runner(script):
        calls.append(script)
        raise RuntimeError("unit adapter failure")

    # Exercise this transport's exception boundary independently of whether
    # the firewall adapter returns an error or propagates a runner exception.
    monkeypatch.setattr("agent.privilege.helper.apply_verified", lambda params, adapter: adapter("unit-only adapter"))
    helper = LoopbackHelper(runner, test_harness=True)

    def exchange(data):
        with socket.create_connection(("127.0.0.1", helper.port), timeout=3) as conn:
            conn.sendall(data + b"\n")
            result = conn.makefile("rb").readline()
        return json.loads(result)

    try:
        request = _envelope(program)
        request["token"] = helper.token
        request["params"]["profile"] = {}
        assert exchange(json.dumps(request).encode())["code"] == "bad_params"
        assert exchange(b"{" * 2000)["code"] == "bad_params"
        request["params"]["profile"] = "Public"
        assert exchange(json.dumps(request).encode())["code"] == "outcome_unknown"
        assert helper._thread.is_alive()
        assert len(calls) == 1
    finally:
        helper.close()


def test_broker_refuses_production_endpoint_without_network_exchange(tmp_path, monkeypatch):
    program = tmp_path / "app.exe"
    program.write_bytes(b"fixture")
    monkeypatch.setattr("agent.privilege.broker._exchange", lambda *_: pytest.fail("production reached token-only endpoint"))
    token = _mutate_depth.set(1)
    try:
        body = submit_restrict_network(_envelope(program)["params"], endpoint={"host": "127.0.0.1", "port": 1, "token": "ab" * 32})
    finally:
        _mutate_depth.reset(token)
    assert body["code"] == "service_unavailable"
    assert body["performed"] is False


def test_pipe_description_does_not_claim_os_enforcement():
    assert PIPE_CLIENT_RIGHTS & 0x4 == 0  # FILE_CREATE_PIPE_INSTANCE
    assert PIPE_CLIENT_RIGHTS & 0x3 == 0x3  # read/write data
    view = describe_pipe("S-1-5-21-100-200-300-400")
    assert view["acl"] == "defined_only"
    assert view["windows"]["server_created"] is False
    assert view["windows"]["remote_rejection_enforced"] is False
    assert view["windows"]["required_pipe_mode"] == 0x8


@pytest.mark.skipif(not shutil.which("powershell.exe"), reason="Windows PowerShell required")
def test_acl_bitmask_owner_ancestor_and_parse_contract():
    common = Path(__file__).resolve().parents[1] / "installer" / "common.ps1"
    # The descriptors exist only in memory. No Set-Acl, task or registry calls.
    code = f". '{str(common).replace(chr(39), chr(39)*2)}'\n" + r"""
$ErrorActionPreference = 'Stop'
function Require { param($Condition, $Message) if (-not $Condition) { throw $Message } }
$acl = Get-DvielleElevationAcl -Directory
Require (Test-DvielleAclDeniesUserWrite $acl) 'ReadAndExecute was classified as write'
$user = New-Object Security.Principal.SecurityIdentifier 'S-1-5-21-100-200-300-400'
$acl.SetOwner($user)
Require (-not (Test-DvielleAclDeniesUserWrite $acl)) 'User owner was accepted'
$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
$acl.AddAccessRule((New-DvielleElevationRule 'S-1-5-21-100-200-300-400' 'WriteData' -Directory))
Require (-not (Test-DvielleAclDeniesUserWrite $acl)) 'User WriteData was accepted'
$parent = Get-DvielleElevationAcl -Directory
$parent.AddAccessRule((New-DvielleElevationRule 'S-1-5-21-100-200-300-400' 'DeleteSubdirectoriesAndFiles' -Directory))
Require (-not (Test-DvielleAclDeniesUserWrite $parent -Ancestor)) 'Parent deletion was accepted'
$sid = 'S-1-5-21-100-200-300-400'
$private = Get-DviellePrivateRuntimeAcl $sid -Directory
Require (Test-DviellePrivateRuntimeAcl $private $sid) 'Installed user cannot write private data'
Require (-not (Test-DvielleAclDeniesUserWrite $private)) 'Private data was accepted as executable trust'
$private.AddAccessRule((New-DvielleElevationRule 'S-1-5-11' 'ReadAndExecute' -Directory))
Require (-not (Test-DviellePrivateRuntimeAcl $private $sid)) 'Shared-readable private data was accepted'

# Pure path/ACL stand-ins. Set-Acl records a plan; no host ACL is changed.
$script:UnitRoot = 'C:\DVielle-Unit'
$script:Descriptors = @{}
$script:Rows = @{}
$script:Children = @{}
$script:AclWrites = @()
foreach ($relative in @('', 'config', 'config\config.yaml', 'data')) {
    $path = $script:UnitRoot
    if ($relative) { $path = Join-Path $path $relative }
    $directory = $relative -ne 'config\config.yaml'
    $attributes = [IO.FileAttributes]::Normal
    if ($directory) { $attributes = [IO.FileAttributes]::Directory }
    $script:Rows[$path] = [pscustomobject]@{ FullName=$path; PSIsContainer=$directory; Attributes=$attributes }
    $script:Descriptors[$path] = Get-DvielleElevationAcl -Directory:$directory
}
$script:Descriptors[(Join-Path $script:UnitRoot 'data')] = Get-DviellePrivateRuntimeAcl $sid -Directory
$script:Children[$script:UnitRoot] = @((Join-Path $script:UnitRoot 'config'), (Join-Path $script:UnitRoot 'data'))
$script:Children[(Join-Path $script:UnitRoot 'config')] = @((Join-Path $script:UnitRoot 'config\config.yaml'))
function Test-DvielleProtectedAncestors { param($Path) return $true }
function Assert-DvielleTreeNoReparse { param($Root, $Path) }
function Get-Item { param($LiteralPath, [switch]$Force, $ErrorAction) return $script:Rows[$LiteralPath] }
function Get-ChildItem {
    param($LiteralPath, [switch]$Force, $ErrorAction)
    foreach ($path in @($script:Children[$LiteralPath])) { if ($path) { $script:Rows[$path] } }
}
function Get-Acl { param($LiteralPath) return $script:Descriptors[$LiteralPath] }
function Test-Path { param($LiteralPath, $PathType) return $script:Rows.ContainsKey($LiteralPath) }
function Set-Acl {
    param($LiteralPath, $AclObject)
    $script:AclWrites += $LiteralPath
    $script:Descriptors[$LiteralPath] = $AclObject
}
Set-DviellePrivateRuntimeTree $script:UnitRoot 'config' $sid
Require ($script:AclWrites.Count -eq 2) 'Unexpected ACL write plan'
Require ($script:AclWrites[0] -eq (Join-Path $script:UnitRoot 'config\config.yaml')) 'Private root was granted before descendants'
Require ($script:AclWrites[1] -eq (Join-Path $script:UnitRoot 'config')) 'Private root was not granted last'
Set-DviellePrivateRuntimeTree $script:UnitRoot 'config' $sid
Require ($script:AclWrites.Count -eq 2) 'Existing mutable private tree had elevated ACL rewrites'
Assert-DvielleTrustedExecutionTree $script:UnitRoot -RuntimePrivateSid $sid
$refused = $false
try { Assert-DvielleTrustedExecutionTree $script:UnitRoot } catch { $refused = $true }
Require $refused 'Private source was accepted as protected executable staging'
$evil = Join-Path $script:UnitRoot 'config-other'
$script:Rows[$evil] = [pscustomobject]@{ FullName=$evil; PSIsContainer=$true; Attributes=[IO.FileAttributes]::Directory }
$script:Descriptors[$evil] = Get-DviellePrivateRuntimeAcl $sid -Directory
$script:Children[$script:UnitRoot] += $evil
$refused = $false
try { Assert-DvielleTrustedExecutionTree $script:UnitRoot -RuntimePrivateSid $sid } catch { $refused = $true }
Require $refused 'Non-allowlisted mutable subtree was accepted'
"""
    # Parse with the known absolute directory rather than an encoded-command path.
    code += f"""
foreach ($name in @('common.ps1', 'install-dvielle.ps1', 'bootstrap-dvielle.ps1', 'elevate.ps1')) {{
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path '{common.parent}' $name), [ref]$null, [ref]$errors)
    Require (-not $errors) ('Parse failure: ' + $name)
}}
"""
    result = subprocess.run([shutil.which("powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.b64encode(code.encode("utf-16-le")).decode()], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_installer_holds_highest_and_checks_source_before_any_old_execution():
    root = Path(__file__).resolve().parents[1]
    install = (root / "installer/install-dvielle.ps1").read_text()
    common = (root / "installer/common.ps1").read_text()
    assert install.index("protected code and private writable data") < install.index("Disable-DvielleOwnedTasks")
    assert install.index("Assert-DvielleTrustedExecutionTree $srcRoot") < install.index("$basePython = Resolve-Python314")
    stop = common[common.index("function Stop-DvielleOwnedRuntime"):common.index("function New-DvielleElevationRule")]
    assert "Invoke-DvielleNative" not in stop
    assert "'-m', 'agent.main'" not in stop
    assert "[IO.Directory]::CreateDirectory($InstallDir, (Get-DvielleElevationAcl -Directory))" in install
    assert "-RuntimePrivateSid $installedUserSid" in install
    create_at = install.index("[IO.Directory]::CreateDirectory")
    verify_at = install.index("Assert-DvielleTrustedExecutionTree $InstallDir", create_at)
    assert verify_at < install.index("Copy-Item", create_at)


def test_wrapper_build_and_native_execution_contracts_are_held_or_resolved():
    root = Path(__file__).resolve().parents[1]
    wrapper = (root / "installer/DVielle.iss").read_text()
    build = (root / "scripts/build_windows_installer.ps1").read_text()
    install = (root / "installer/install-dvielle.ps1").read_text()
    elevate = (root / "installer/elevate.ps1").read_text()
    common = (root / "installer/common.ps1").read_text()
    branding = (root / "scripts/New-DvielleGuiExe.ps1").read_text()
    assert "InitializeSetup: Boolean" in wrapper and "Result := False;" in wrapper
    assert "CurStepChanged" not in wrapper and "if not Exec(" not in wrapper
    assert build.index("throw 'Setup wrapper builds are held") < build.index("New-Item")
    assert "Invoke-DvielleNative 'auditpol.exe'" not in install
    assert "Start-Process -FilePath 'powershell.exe'" not in elevate
    assert "GetFolderPath([Environment+SpecialFolder]::System)" in common
    assert "Assert-DvielleTrustedExecutionTree $program" in common
    assert "Missing mandatory installer/rcedit-x64.pin.json" in branding
