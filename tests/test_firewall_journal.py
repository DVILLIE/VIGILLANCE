"""Recovery contracts with injected runners; no host firewall mutation."""
import json
import base64
import shutil
import subprocess
import pytest

from agent.modules import firewall_apply as firewall
from agent.local_files import atomic_text


@pytest.fixture
def firewall_request(tmp_path):
    program = tmp_path / "program.exe"
    program.write_bytes(b"owned test fixture")
    return {"program": str(program), "profile": "Public", "address_families": ["IPv4"],
            "remote_addresses": ["192.0.2.1/32"]}


def good_output(firewall_request, token):
    name = firewall.rule_names(firewall_request["program"], "Public", ["IPv4"], ["192.0.2.1/32"])[0][0]
    return (f"VERIFY:{name}|True|Outbound|Block|Public|derived|{firewall_request['program']}|"
            f"192.0.2.1/32|DVielle|DVielle invocation {token}\nSTATUS:OK"), False


def test_durable_intent_precedes_runner_and_pending_blocks_retry(tmp_path, firewall_request):
    path = tmp_path / "journal.json"
    calls = []
    def runner(script):
        record = json.loads(path.read_text())
        assert record["state"] == "intent_durable"
        assert record["params"] == firewall_request
        calls.append(script)
        return good_output(firewall_request, record["ownership_token"])
    with firewall.apply_scope():
        result = firewall.apply_verified(firewall_request, runner, journal_path=path)
        assert result["ok"] and result["journal_state"] == "configuration_verified"
        assert firewall.apply_verified(firewall_request, runner, journal_path=path)["code"] == "recovery_required"
    assert len(calls) == 1


def test_live_default_refused_without_journal(monkeypatch, firewall_request):
    monkeypatch.setattr(firewall, "_default_runner", lambda _: pytest.fail("must not execute"))
    with firewall.apply_scope():
        assert firewall.apply_verified(firewall_request)["code"] == "journal_unavailable"


def test_failed_journal_write_cannot_execute(monkeypatch, tmp_path, firewall_request):
    def fail(*args):
        raise OSError("disk unavailable")
    monkeypatch.setattr(firewall, "atomic_text", fail)
    with firewall.apply_scope():
        result = firewall.apply_verified(firewall_request, lambda _: pytest.fail("must not execute"),
                                         journal_path=tmp_path / "journal.json")
    assert result["state_unknown"]


def test_failed_commands_retain_unknown_intent(tmp_path, firewall_request):
    path = tmp_path / "journal.json"
    def fail(_):
        raise OSError("runner unavailable")
    with firewall.apply_scope():
        result = firewall.apply_verified(firewall_request, fail, journal_path=path)
    assert not result["ok"]
    assert json.loads(path.read_text())["state"] == "outcome_unknown"


@pytest.mark.parametrize("conflict", [False, True])
def test_recovery_preserves_conflicts_and_checks_scope(tmp_path, firewall_request, conflict):
    path = tmp_path / "journal.json"
    with firewall.apply_scope():
        firewall.apply_verified(firewall_request, lambda _: good_output(firewall_request, "fixture"), journal_path=path)
    assert firewall.restore_journal(path, lambda _: pytest.fail("scope required"))["code"] == "refused"
    def remove(script):
        record = json.loads(path.read_text())
        assert record["state"] == "outcome_unknown"
        assert script.index("$actual -ne $wanted") < script.index("Remove-NetFirewallRule -InputObject")
        name = record["rule_names"][0]
        return (f"REMOVE:FAILED:{name}\nREMOVE:UNTOUCHED:{name}\nSTATUS:OK" if conflict else
                f"REMOVE:GONE:{name}\nSTATUS:OK"), False
    with firewall.apply_scope():
        result = firewall.restore_journal(path, remove)
    assert result["ok"] is (not conflict)
    assert json.loads(path.read_text())["state"] == ("outcome_unknown" if conflict else "restored")


def test_atomic_text_replaces_and_leaves_no_staging_files(tmp_path):
    path = tmp_path / "intent.json"
    atomic_text(path, "first")
    atomic_text(path, "second")
    assert path.read_text() == "second"
    assert list(tmp_path.iterdir()) == [path]


def test_windows_parses_generated_apply_and_conditional_restore(firewall_request):
    executable = shutil.which("powershell.exe")
    if executable is None:
        pytest.skip("Windows PowerShell parser is unavailable")
    names = [name for name, _ in firewall.rule_names(firewall_request["program"], "Public", ["IPv4"], ["192.0.2.1/32"])]
    for script in (firewall.apply_script(firewall_request, ownership_token="a" * 32),
                   firewall.remove_script(names, ownership_token="a" * 32, expected=firewall_request)):
        source = base64.b64encode(script.encode()).decode()
        code = ("$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + source + "')); "
                "$errors = $null; $null = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$errors); "
                "if ($errors) { $errors | ConvertTo-Json -Compress; exit 1 }; exit 0")
        encoded = base64.b64encode(code.encode("utf-16-le")).decode()
        result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr


def test_windows_restore_normalizes_equivalent_network_representations():
    """Execute the pure address comparison in real Windows PowerShell; no rules change."""
    executable = shutil.which('powershell.exe')
    if executable is None:
        pytest.skip('Windows PowerShell is unavailable')
    script = firewall.remove_script([])
    function = script[script.index('function ConvertTo-DvielleRemoteSet'):script.index('$names =')]
    code = "$ErrorActionPreference='Stop';" + function + r'''
if ((ConvertTo-DvielleRemoteSet @('192.0.2.1')) -cne (ConvertTo-DvielleRemoteSet @('192.0.2.1/32'))) { throw 'Host mismatch' }
if ((ConvertTo-DvielleRemoteSet @('2001:DB8::1')) -cne (ConvertTo-DvielleRemoteSet @('2001:db8::1/128'))) { throw 'IPv6 mismatch' }
if ((ConvertTo-DvielleRemoteSet @('192.0.2.99/24')) -cne '192.0.2.0/24') { throw 'Network mask mismatch' }
if ((ConvertTo-DvielleRemoteSet @('192.0.2.1')) -ceq (ConvertTo-DvielleRemoteSet @('192.0.2.2'))) { throw 'Different hosts accepted' }
$rejected=$false
try { ConvertTo-DvielleRemoteSet @('Any') } catch { $rejected=$true }
if (-not $rejected) { throw 'Unknown scope accepted' }
'''
    encoded = base64.b64encode(code.encode('utf-16-le')).decode()
    result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr

