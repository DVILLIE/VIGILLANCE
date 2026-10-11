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
from agent.local_files import file_lock
from agent.policy.dual import DualGate
from agent.store.db import AgentStore, utc_now


def _append_log(log_dir: Path, name: str, line: str) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"{name}.txt"
    payload = (line[:65536] + "\n").encode("utf-8")
    with file_lock(log_dir / f".{name}.lock"):
        if path.exists() and path.stat().st_size + len(payload) > 1024 * 1024:
            oldest = path.with_name(path.name + ".2")
            previous = path.with_name(path.name + ".1")
            oldest.unlink(missing_ok=True)
            if previous.exists():
                previous.replace(oldest)
            path.replace(previous)
        with path.open("ab") as handle:
            handle.write(payload)


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

        finding, created = self.store.stage_finding(finding)
        if finding.get('action_claimed') or finding.get('recovery_required'):
            return {"disposition": "ticket", "keep_on_match": match.code, "finding": finding, "mutated": False}
        if finding.get("snooze_until") and finding["snooze_until"] > self.now():
            return {"disposition": "snoozed", "keep_on_match": match.code, "finding": finding, "mutated": False}

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
                if auto is not None:
                    return auto
                finding = self.store.get_finding(finding['id']) or finding
        if not created:
            return {"disposition": "ticket", "keep_on_match": match.code, "finding": finding, "mutated": False}
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
        if option['effect'] == 'show_why':
            # Evidence must remain readable while dispatch/recovery is held.
            # Do not change the authoritative workflow or action state.
            finding['last_result'] = finding['why_it_matters'] + '\n' + '\n'.join(
                f'- {ref}' for ref in finding['evidence_refs'])
            return finding

        finding = self.store.claim_finding(finding_id, self.now())
        if finding is None:
            raise PolicyDenied("that finding is already being handled or needs recovery")
        option = next((item for item in finding["options"] if item["id"] == option_id), None)
        if option is None:
            self._release_without_dispatch(finding)
            raise PolicyDenied('The options changed; reopen the card')
        effect = option["effect"]
        try:
            local = self._select_local(finding, option, option_id)
            if local is not None:
                return local
            token = self.policy.issue(
                finding['id'], option['handler'], auto=False,
                subject=str(finding.get('subject_identity') or ''),
            )
        except Exception:
            self._release_without_dispatch(finding)
            raise
        try:
            result = self.handlers.invoke(option["handler"], finding, self.handler_ctx, token)
        except Exception as exc:
            self._log("errors", f"ERROR handler {option.get('handler')} failed: {exc}")
            finding["resolution_status"] = "in_progress"
            finding['recovery_required'] = True
            finding["last_result"] = "Action outcome is unknown. Review its effects before retrying."
            self.store.save_finding(finding, action_owner=True)
            raise
        finding["last_result"] = result["message"]
        reported = result.get("status")
        if _needs_recovery(result):
            finding['resolution_status'] = 'in_progress'
            finding['recovery_required'] = True
        elif reported in ("found", "in_progress", "resolved", "monitoring", "dismissed"):
            finding["resolution_status"] = reported
        elif effect == "preview" or not result["performed"]:
            finding["resolution_status"] = "monitoring" if effect == "guidance" else "found"
        else:
            finding["resolution_status"] = "resolved"
        self._log(finding["pillar"], f"INFO option={option_id} status={finding['resolution_status']} {result['message']}")
        self._finish(finding, option_id, result["message"], result["performed"])
        return finding

    def _select_local(self, finding: dict, option: dict, option_id: str) -> dict | None:
        effect = option['effect']
        if effect == 'snooze':
            current = datetime.fromisoformat(self.now())
            finding['snooze_until'] = (current + timedelta(seconds=self.cooldown_seconds)).isoformat()
            finding['resolution_status'] = 'monitoring'
            finding['last_result'] = option['what_we_will_do']
        elif effect == 'learn':
            self.memory.set(finding['pillar'], finding['subject_identity'], option['decision'],
                            self.now(), notes=option['label'])
            finding['resolution_status'] = option.get('resulting_status') or 'monitoring'
            finding['last_result'] = option['what_we_will_do']
            if self.memory.mirror_errors:
                finding['last_result'] += ' Your decision was saved; some local summary files could not be refreshed.'
                self._log('errors', 'WARNING keep-on mirrors need refresh: ' + ', '.join(self.memory.mirror_errors))
            self._log(finding['pillar'], f"INFO learned {option['decision']} {finding['subject_identity']}")
        else:
            return None
        self._finish(finding, option_id, finding['last_result'], False)
        return finding

    def _release_without_dispatch(self, finding: dict) -> None:
        if finding['resolution_status'] == 'in_progress':
            finding['resolution_status'] = finding.get('action_previous_status', 'found')
        finding['action_claimed'] = False
        finding.pop('action_previous_status', None)
        finding['updated_at'] = self.now()
        self.store.save_finding(finding, action_owner=True)

    def mutate(self, finding_id: str, handler: str, token=None) -> None:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            raise FailClosed("no such finding")
        # This legacy entry point must not bypass
        # the reservation and result ledger owned by select()/automatic actions.
        raise PolicyDenied('options required before mutate; use an approved options card')

    def _try_auto(self, finding: dict, handler: str) -> dict | None:
        if self.experience is not None:
            from agent.experiences import experience_allows_auto

            allowed, reason = experience_allows_auto(
                self.experience, handler, severity=str(finding.get("severity") or "")
            )
            if not allowed:
                self._log("errors", f"ERROR auto-protect refused: {reason}")
                return None
        reserved = None
        try:
            token = self.policy.issue(
                finding["id"],
                handler,
                auto=True,
                subject=str(finding.get("subject_identity") or ""),
                severity=str(finding.get("severity") or ""),
            )
            reserved = self.store.claim_finding(finding['id'], self.now())
            if reserved is None:
                return {"disposition": "ticket", "keep_on_match": finding['keep_on_match'],
                        "finding": self.store.get_finding(finding['id']), "mutated": False}
            finding = reserved
            if (finding['action_class'] != 'auto_protect_eligible'
                    or finding['confidence'] != 'high'
                    or not finding['signals'].get('identity_ok')
                    or finding['keep_on_match'] == 'suspicious_mismatch'):
                # Another observer may have replaced the evidence after staging.
                self._release_without_dispatch(finding)
                return None
            result = self.handlers.invoke(handler, finding, self.handler_ctx, token)
        except PolicyDenied as exc:
            self._log("errors", f"ERROR auto-protect refused: {exc}")
            if reserved is not None:
                # A mutator exception can be wrapped as PolicyDenied by the
                # executor. After dispatch, absence of a result is ambiguous.
                finding['last_result'] = 'Automatic action outcome is unknown. Review its effects before retrying.'
                finding['recovery_required'] = True
                self.store.save_finding(finding, action_owner=True)
                return {'disposition': 'error', 'keep_on_match': finding['keep_on_match'],
                        'finding': finding, 'mutated': None}
            return None
        except Exception as exc:
            finding['last_result'] = 'Automatic action outcome is unknown. Review its effects before retrying.'
            if reserved is not None:
                finding['recovery_required'] = True
                self.store.save_finding(finding, action_owner=True)
            self._log('errors', f'ERROR automatic handler {handler} failed: {exc}')
            return {'disposition': 'error', 'keep_on_match': finding['keep_on_match'],
                    'finding': finding, 'mutated': None if reserved is not None else False}
        self._log("autoprotect", f"INFO finding={finding['id']} handler={handler} performed={result['performed']} {result['message']}")
        finding["last_result"] = result["message"]
        if _needs_recovery(result):
            finding['recovery_required'] = True
            self.store.save_finding(finding, action_owner=True)
            return {'disposition': 'error', 'keep_on_match': finding['keep_on_match'],
                    'finding': finding, 'mutated': True if result['performed'] else None}
        if result["performed"]:
            finding['action_claimed'] = False
            finding.pop('action_previous_status', None)
            finding["resolution_status"] = "resolved"
            finding["updated_at"] = self.now()
            self.store.save_finding(finding, action_owner=True)
            return {"disposition": "auto_protect", "keep_on_match": finding["keep_on_match"], "finding": finding, "mutated": True}
        finding['resolution_status'] = 'found'
        finding['action_claimed'] = False
        finding.pop('action_previous_status', None)
        self.store.save_finding(finding, action_owner=True)
        return None

    def _finish(self, finding: dict, option_id: str, message: str, mutated: bool) -> None:
        finding['action_claimed'] = bool(finding.get('recovery_required'))
        if not finding['action_claimed']:
            finding.pop('action_previous_status', None)
        finding["updated_at"] = self.now()
        if not self.store.save_finding(finding, action_owner=True):
            raise PolicyDenied('The action reservation changed; inspect the current finding')
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
            "action_claimed": False,
            "recovery_required": False,
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


def _needs_recovery(result: dict) -> bool:
    return bool(result.get('state_unknown') or result.get('live_state_unknown') or result.get('recovery_pending')
                or result.get('code') == 'outcome_unknown')


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
