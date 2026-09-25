"""Quiet only when an allow still matches the real subject.

A suspicious mismatch always speaks, including after allow or never-warn.
"""

from __future__ import annotations

from agent.engine.models import KeepOnMatch, Observation
from agent.learn.memory import KeepOnRecord


def match_keep_on(record: KeepOnRecord | None, obs: Observation) -> KeepOnMatch:
    if not obs.subject_identity:
        return KeepOnMatch("n/a", "ticket")

    allowed = record is not None and record.decision == "allow"
    looks_wrong = obs.suspicious_mismatch or (
        allowed and obs.quiet_on_allow and (not obs.identity_ok or not obs.expected)
    )
    if looks_wrong:
        return KeepOnMatch("suspicious_mismatch", "ticket")

    if record is not None and record.decision == "never_warn":
        return KeepOnMatch("n/a", "quiet_never_warn")

    if allowed and obs.quiet_on_allow and obs.identity_ok and obs.expected:
        return KeepOnMatch("allowed_and_expected", "quiet")

    if record is None and obs.baseline_expected and obs.identity_ok and obs.expected:
        return KeepOnMatch("n/a", "quiet_baseline")

    if record is None:
        return KeepOnMatch("unknown", "ticket")
    if record.decision == "deny":
        return KeepOnMatch("denied", "ticket")
    if record.decision == "ask_always":
        return KeepOnMatch("unknown", "ticket")
    if allowed and not obs.quiet_on_allow:
        return KeepOnMatch("unknown", "ticket")
    return KeepOnMatch("unknown", "ticket")
