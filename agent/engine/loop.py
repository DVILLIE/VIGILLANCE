"""Observe → match keep-on → quiet, or options card → perform that one choice."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from pathlib import Path

from agent.engine.catalogs import options_for
from agent.engine.handlers import (
    HandlerContext,
    HandlerRegistry,
    default_close,
    default_lookup,
    register_default_handlers,
)
from agent.engine.keep_on import match_keep_on
from agent.engine.models import QUIET, FailClosed, Observation, PolicyDenied
from agent.engine.policy import PolicyGate
from agent.learn.memory import KeepOnMemory
from agent.policy.dual import DualGate
from agent.store.db import AgentStore, utc_now


def _append_log(log_dir: Path, name: str, line: str) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"{name}.txt"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


class ResolutionEngine:
    """Shared by Safety, Speed, and Storage. Other pillars can pass observations too."""

    def __init__(
        self,
        store: AgentStore,
        *,
        learn_dir: Path | None = None,
        log_dir: Path | None = None,
        handler_ctx: HandlerContext | None = None,
        now=None,
        cooldown_seconds: int = 6 * 60 * 60,
        auto_enabled: bool | None = None,
        experience: dict | None = None,
    ) -> None:
        data_dir = store.db_path.parent
        self.store = store
        self.memory = KeepOnMemory(learn_dir or (data_dir / "learn"))
        self.log_dir = log_dir or (data_dir / "logs")
        self.now = now or utc_now
        self.cooldown_seconds = cooldown_seconds
        self.handler_ctx = handler_ctx or HandlerContext(lookup=default_lookup, close=default_close)
        if self.handler_ctx.learn_dir is None:
            self.handler_ctx.learn_dir = self.memory.learn_dir
        if self.handler_ctx.helper_endpoint is None:
            from agent.privilege.broker import discover_endpoint

            self.handler_ctx.helper_endpoint = discover_endpoint(data_dir)
        enabled = auto_enabled
        if enabled is None:
            enabled = _read_auto(self.memory.learn_dir / "auto_protect.txt")
        self.experience = experience
        self.policy = PolicyGate(auto_enabled=enabled, experience=experience)
        self.dual = DualGate(self.store, self.policy, experience)
        self.handlers = HandlerRegistry(self.policy, self.dual)
        register_default_handlers(self.handlers)

    def evaluate(self, obs: Observation, *, force_surface: bool = False) -> dict:
        record = self.memory.get(obs.pillar, obs.subject_identity) if obs.subject_identity else None
        try:
            match = match_keep_on(record, obs)
        except Exception as exc:
            self._log("errors", f"ERROR match failed: {exc}")
            return {"disposition": "error", "keep_on_match": "n/a", "finding": None, "mutated": False}

        if match.disposition in QUIET and not force_surface:
            self._log(obs.pillar, f"INFO quiet {obs.kind} {obs.subject_identity} {match.code}")
            return {"disposition": match.disposition, "keep_on_match": match.code, "finding": None, "mutated": False}

        if not force_surface and not _should_surface(obs, self.experience):
            self._log("activity", f"INFO held {obs.pillar} {obs.subject_identity} {obs.severity} {obs.confidence}")
            return {"disposition": "held", "keep_on_match": match.code, "finding": None, "mutated": False}

        try:
            finding = self._build(obs, match.code)
        except FailClosed as exc:
            self._log("errors", f"ERROR {exc}")
            return {"disposition": "error", "keep_on_match": match.code, "finding": None, "mutated": False}

        if (
            self.policy.auto_enabled
            and obs.action_class == "auto_protect_eligible"
            and obs.confidence == "high"
            and obs.identity_ok
            and not obs.suspicious_mismatch
            and (record is None or record.decision != "never_warn")
        ):
            handler = _auto_handler(obs)
            if handler:
                auto = self._try_auto(finding, handler)
                if auto and auto.get("mutated"):
                    return auto

        existing = self.store.find_active_finding(obs.pillar, obs.subject_identity, obs.kind)
        if existing and existing.get("snooze_until") and existing["snooze_until"] > self.now():
            return {"disposition": "snoozed", "keep_on_match": match.code, "finding": existing, "mutated": False}
        if existing:
            existing["evidence_refs"] = finding["evidence_refs"]
            existing["signals"] = finding["signals"]
            existing["title_simple"] = finding["title_simple"]
            existing["keep_on_match"] = match.code
            existing["updated_at"] = self.now()
            if match.code == "suspicious_mismatch":
                existing["resolution_status"] = "found"
                existing["snooze_until"] = None
            self.store.save_finding(existing)
            return {"disposition": "ticket", "keep_on_match": match.code, "finding": existing, "mutated": False}

        self.store.save_finding(finding)
        self.store.log_event(
            obs.pillar,
            "WARNING" if obs.severity in ("high", "critical") else "INFO",
            finding["title_simple"],
            {"finding_id": finding["id"], "keep_on_match": match.code},
        )
        self._log(obs.pillar, f"INFO ticket {finding['id']} {match.code} {finding['title_simple']}")
        return {"disposition": "ticket", "keep_on_match": match.code, "finding": finding, "mutated": False}

    def select(self, finding_id: str, option_id: str) -> dict:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            raise FailClosed("no such finding")
        if finding["resolution_status"] in ("resolved", "dismissed"):
            raise PolicyDenied("that finding is already closed")
        option = next((item for item in finding["options"] if item["id"] == option_id), None)
        if option is None:
            raise PolicyDenied("unknown option")

        finding["resolution_status"] = "in_progress"
        finding["updated_at"] = self.now()
        self.store.save_finding(finding)
        effect = option["effect"]

        if effect == "show_why":
            message = finding["why_it_matters"] + "\n" + "\n".join(f"- {ref}" for ref in finding["evidence_refs"])
            finding["last_result"] = message
            finding["resolution_status"] = "found"
            self._finish(finding, option_id, message, False)
            return finding

        if effect == "snooze":
            current = datetime.fromisoformat(self.now())
            finding["snooze_until"] = (current + timedelta(seconds=self.cooldown_seconds)).isoformat()
            finding["resolution_status"] = "monitoring"
            finding["last_result"] = option["what_we_will_do"]
            self._finish(finding, option_id, finding["last_result"], False)
            return finding

        if effect == "learn":
            self.memory.set(
                finding["pillar"],
                finding["subject_identity"],
                option["decision"],
                self.now(),
                notes=option["label"],
            )
            finding["resolution_status"] = option.get("resulting_status") or "monitoring"
            finding["last_result"] = option["what_we_will_do"]
            self._log(finding["pillar"], f"INFO learned {option['decision']} {finding['subject_identity']}")
            self._finish(finding, option_id, finding["last_result"], False)
            return finding

        token = self.policy.issue(
            finding["id"],
            option["handler"],
            auto=False,
            subject=str(finding.get("subject_identity") or ""),
        )
        try:
            result = self.handlers.invoke(option["handler"], finding, self.handler_ctx, token)
        except Exception as exc:
            self._log("errors", f"ERROR handler {option.get('handler')} failed: {exc}")
            finding["resolution_status"] = "found"
            finding["last_result"] = "DVielle could not finish that action. Nothing was marked fixed."
            self.store.save_finding(finding)
            raise
        finding["last_result"] = result["message"]
        reported = result.get("status")
        if reported in ("found", "in_progress", "resolved", "monitoring", "dismissed"):
            finding["resolution_status"] = reported
        elif effect == "preview" or not result["performed"]:
            finding["resolution_status"] = "monitoring" if effect == "guidance" else "found"
        else:
            finding["resolution_status"] = "resolved"
        self._log(finding["pillar"], f"INFO option={option_id} status={finding['resolution_status']} {result['message']}")
        self._finish(finding, option_id, result["message"], result["performed"])
        return finding

    def mutate(self, finding_id: str, handler: str, token=None) -> None:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            raise FailClosed("no such finding")
        self.handlers.invoke(handler, finding, self.handler_ctx, token)

    def _try_auto(self, finding: dict, handler: str) -> dict | None:
        if self.experience is not None:
            from agent.experiences import experience_allows_auto

            allowed, reason = experience_allows_auto(
                self.experience, handler, severity=str(finding.get("severity") or "")
            )
            if not allowed:
                self._log("errors", f"ERROR auto-protect refused: {reason}")
                return None
        try:
            token = self.policy.issue(
                finding["id"],
                handler,
                auto=True,
                subject=str(finding.get("subject_identity") or ""),
                severity=str(finding.get("severity") or ""),
            )
            result = self.handlers.invoke(handler, finding, self.handler_ctx, token)
        except PolicyDenied as exc:
            self._log("errors", f"ERROR auto-protect refused: {exc}")
            return None
        self._log("autoprotect", f"INFO finding={finding['id']} handler={handler} performed={result['performed']} {result['message']}")
        finding["last_result"] = result["message"]
        if result["performed"]:
            finding["resolution_status"] = "resolved"
            finding["updated_at"] = self.now()
            self.store.save_finding(finding)
            return {"disposition": "auto_protect", "keep_on_match": finding["keep_on_match"], "finding": finding, "mutated": True}
        return None

    def _finish(self, finding: dict, option_id: str, message: str, mutated: bool) -> None:
        finding["updated_at"] = self.now()
        self.store.save_finding(finding)
        self.store.log_work(f"OPTION:{option_id}", message, {"finding_id": finding["id"], "mutated": mutated})

    def _build(self, obs: Observation, match_code: str) -> dict:
        options = [item.to_dict() for item in options_for(obs.pillar, obs.kind)]
        if obs.action_class in ("ask_user", "auto_protect_eligible") and not options:
            raise FailClosed("ask_user findings require options")
        now = self.now()
        signals = dict(obs.signals)
        signals["identity_ok"] = obs.identity_ok
        return {
            "id": "f" + uuid.uuid4().hex[:12],
            "pillar": obs.pillar,
            "kind": obs.kind,
            "title_simple": obs.title_simple,
            "why_it_matters": obs.why_it_matters,
            "if_ignored": obs.if_ignored,
            "evidence_refs": list(obs.evidence_refs),
            "severity": obs.severity,
            "confidence": obs.confidence,
            "recommended_action": obs.recommended_action,
            "resolution_steps": list(obs.resolution_steps),
            "resolution_status": "found",
            "action_class": obs.action_class,
            "options": options,
            "subject_identity": obs.subject_identity,
            "keep_on_match": match_code,
            "reversible": obs.reversible,
            "signals": signals,
            "created_at": now,
            "updated_at": now,
            "snooze_until": None,
            "last_result": None,
        }

    def _log(self, name: str, message: str) -> None:
        _append_log(self.log_dir, name, f"{self.now()} {message}")


def _should_surface(obs: Observation, experience: dict | None = None) -> bool:
    if experience is not None:
        from agent.experiences import experience_surfaces

        return experience_surfaces(experience, obs.severity, obs.confidence)
    if obs.confidence not in ("medium", "high"):
        return False
    return obs.severity in ("medium", "high", "critical")


def _auto_handler(obs: Observation) -> str | None:
    if obs.kind == "safe_temp" and obs.signals.get("critical_free") is True:
        return "storage.free_safe_temp"
    if obs.kind == "protection_off":
        return "safety.turn_protection_on"
    return None


def _read_auto(path: Path) -> bool:
    if not path.exists():
        return False
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip().startswith("enabled="):
            return raw.split("=", 1)[1].strip().lower() == "true"
    return False
