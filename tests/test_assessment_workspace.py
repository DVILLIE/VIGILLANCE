"""Scope/ledger regressions and real requests to an owned loopback server."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent.assessment import AssessmentEngine, AssessmentScope
from agent.assessment.engine import AssessmentStopped, utc
from agent.local_files import file_lock


@pytest.mark.parametrize("target", ["https://user:secret@example.org", "https://example.org/path",
    "https://example.org?secret=x", "https://example.org#fragment", "ftp://example.org",
    "https://exa\nmple.org", "https://example.org:99999", "https://example.org:0"])
def test_invalid_scope_refused_before_ledger(tmp_path, target):
    engine = AssessmentEngine(tmp_path)
    with pytest.raises(ValueError):
        engine.run(AssessmentScope(target, "Owned asset", True, time.time() + 60))
    assert engine.history() == []


def test_unapproved_or_expired_scope_no_request(tmp_path):
    engine = AssessmentEngine(tmp_path)
    with pytest.raises(ValueError):
        engine.run(AssessmentScope("https://example.org", "Owned", False, time.time() + 60))
    with pytest.raises(AssessmentStopped):
        engine.run(AssessmentScope("https://example.org", "Owned", True, time.time() - 1))
    with pytest.raises(ValueError):
        engine.run(AssessmentScope("https://example.org", "Owned", True, float("nan")))
    assert engine.history() == []


def test_preexisting_stop_does_not_create_run(tmp_path):
    stop = threading.Event()
    stop.set()
    engine = AssessmentEngine(tmp_path)
    with pytest.raises(AssessmentStopped):
        engine.run(AssessmentScope(), stop)
    assert engine.history() == []


@pytest.fixture
def owned_server():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append((self.command, self.path))
            self.send_response(302)
            self.send_header("Location", "http://outside-authorization.invalid/")
            self.send_header("Content-Security-Policy", "default-src https://private.example.invalid")
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_actual_origin_request_stays_at_root_and_never_follows_redirect(tmp_path, owned_server):
    origin, requests = owned_server
    engine = AssessmentEngine(tmp_path / "ledger")
    report = engine.run(AssessmentScope(origin, "Owned loopback test server", True, time.time() + 60))
    assert report["state"] == "completed"
    assert requests == [("HEAD", "/")]
    assert report["observations"]["http_status"] == 302
    assert report["mutations"] == []
    assert any("not followed" in item for item in report["coverage"])
    assert engine.report(report["id"]) == report
    output = tmp_path / "report.json"
    engine.export(report["id"], output)
    exported = json.loads(output.read_text())
    assert exported["scope"]["target"] == "[redacted origin]"
    assert "127.0.0.1" not in output.read_text()
    assert "private.example.invalid" not in output.read_text()
    assert exported["observations"]["security_headers"]["content-security-policy"] == "present"
    assert engine.report(report["id"])["scope"]["target"] == origin


def test_lock_prevents_overlapping_assessment(tmp_path):
    engine = AssessmentEngine(tmp_path)
    with file_lock(tmp_path / "assessment.lock"):
        with pytest.raises(TimeoutError):
            engine.run(AssessmentScope())
    assert engine.history() == []


def test_new_console_does_not_relabel_live_run(tmp_path):
    engine = AssessmentEngine(tmp_path)
    report = {"id": "previous", "started": utc(), "state": "running", "scope": {}, "findings": []}
    engine._save(report, insert=True)
    second = AssessmentEngine(tmp_path)
    assert second.history()[0]["state"] == "running"
    with file_lock(tmp_path / "assessment.lock"):
        second._reconcile_interrupted()
    assert second.report("previous")["state"] == "interrupted"
    assert "partial" in second.report("previous")["detail"]


def test_failure_retains_partial_evidence_without_success_claim(tmp_path, monkeypatch):
    engine = AssessmentEngine(tmp_path)

    def failing(scope, stop, report):
        report["observations"]["recorded_before_failure"] = True
        raise OSError("private-path-not-for-export")

    monkeypatch.setattr(engine, "_local", failing)
    report = engine.run(AssessmentScope())
    assert report["state"] == "failed"
    assert report["observations"]["recorded_before_failure"]
    assert "private-path" not in report["detail"]
    assert engine.history()[0]["state"] == "failed"


def test_version_sharing_requires_fresh_per_run_authorization(tmp_path):
    engine = AssessmentEngine(tmp_path)
    with pytest.raises(ValueError):
        engine.run(AssessmentScope(share_runtime_versions=True))
    with pytest.raises(AssessmentStopped):
        engine.run(AssessmentScope(authorized=True, share_runtime_versions=True, expires_at=time.time() - 1))
    assert engine.history() == []
