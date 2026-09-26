"""Footprint Resolution Center. Local tickets and playbooks. No people search."""

from __future__ import annotations

import os
from pathlib import Path

from agent.engine.models import Observation

REMOTE_KINDS = ("breach_hit", "public_search", "broker_listing", "dark_web_alert")
LOCAL_KINDS = ("exposure", "local_residue")
KINDS = LOCAL_KINDS + REMOTE_KINDS
PROGRESS_STATUSES = ("found", "in_progress", "resolved", "monitoring", "dismissed")

# Public homepages only. DVielle does not call these services.
PARTNERS = (
    {"id": "deleteme", "name": "DeleteMe", "url": "https://joindeleteme.com/", "role": "broker removal"},
    {"id": "incogni", "name": "Incogni", "url": "https://incogni.com/", "role": "broker removal"},
    {"id": "aura", "name": "Aura", "url": "https://www.aura.com/", "role": "monitoring and removal"},
    {"id": "lifelock", "name": "LifeLock", "url": "https://www.lifelock.com/", "role": "monitoring"},
    {"id": "remove", "name": "REMOVE", "url": "https://remove.dev/", "role": "broker removal"},
)

_HEADER = (
    "# DVielle footprint resolution progress. Local only. No email addresses.\n"
    "# subject|status|partner|timestamp|notes\n"
)


def _atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class FootprintProgress:
    """Checklist and partner state. Never a dump of emails or other people's names."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.rows: dict[str, dict[str, str]] = {}
        self.load()

    def load(self) -> None:
        self.rows.clear()
        if not self.path.exists():
            return
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "@" in line:
                continue
            parts = line.split("|", 4)
            if len(parts) < 4 or parts[1] not in PROGRESS_STATUSES:
                continue
            self.rows[parts[0]] = {
                "status": parts[1],
                "partner": parts[2],
                "updated": parts[3],
                "notes": parts[4] if len(parts) > 4 else "",
            }

    def get(self, subject: str) -> str | None:
        row = self.rows.get(subject)
        return row["status"] if row else None

    def record(self, subject: str, status: str, updated: str, partner: str = "", notes: str = "") -> None:
        if status not in PROGRESS_STATUSES:
            raise ValueError(f"unknown footprint status: {status}")
        blob = f"{subject}|{partner}|{notes}"
        if "@" in blob or "\n" in blob or "|" in subject:
            raise ValueError("footprint progress cannot store an email address")
        self.rows[subject] = {
            "status": status,
            "partner": partner.replace("|", "/")[:80],
            "updated": updated,
            "notes": notes.replace("\n", " ").replace("|", "/")[:200],
        }
        self.save()

    def save(self) -> None:
        lines = [_HEADER.rstrip("\n")]
        for subject in sorted(self.rows):
            row = self.rows[subject]
            lines.append(
                f"{subject}|{row['status']}|{row['partner']}|{row['updated']}|{row['notes']}"
            )
        _atomic(self.path, "\n".join(lines) + "\n")


def partner_playbook() -> str:
    lines = [
        "Partner removal and monitoring is optional. Examples, not a required account:",
    ]
    for item in PARTNERS:
        lines.append(f"- {item['name']} ({item['role']}): {item['url']}")
    lines.append(
        "DVielle did not enroll you, did not submit an opt-out, and did not erase data from the internet."
    )
    return "\n".join(lines)


def observation_from_footprint(fact: dict) -> Observation | None:
    """A resolution ticket for this machine only. Remote hits must be marked synthetic."""
    target = fact.get("target") or "self"
    if target != "self":
        return None
    kind = str(fact.get("kind") or "exposure")
    if kind not in KINDS:
        return None
    if kind in REMOTE_KINDS and not fact.get("synthetic"):
        return None
    label = str(fact.get("label") or kind).strip()
    if not label or "@" in label or "|" in label or "\n" in label:
        return None
    synthetic = bool(fact.get("synthetic"))
    subject = f"footprint:{kind}:{label.lower()}"
    if kind == "local_residue":
        title = "Accounts on this PC may still be signed in"
        why = (
            "Signing out of unused accounts and turning on two-factor login locks this computer. "
            "DVielle did not search the internet for a person."
        )
    elif kind == "breach_hit":
        title = "Drill: a breach checklist is ready for your own email"
        why = (
            "This is a fixture, not a live breach search. "
            "A real check sends your email off this device. "
            "DVielle will not look up someone else, and this app cannot erase every copy on the internet."
        )
    elif kind == "broker_listing":
        title = "Drill: a people-search listing can be tracked to done"
        why = (
            "This is a fixture. The free path is a do-it-yourself opt-out. "
            "The faster path is a removal service that keeps checking when a listing comes back. "
            "DVielle did not search another person and did not erase the internet."
        )
    elif kind == "public_search":
        title = "Drill: a public-page ticket can go to a takedown or opt-out"
        why = (
            "This is a fixture. You can open a takedown or opt-out checklist, or a partner. "
            "DVielle did not search the web for a name."
        )
    elif kind == "dark_web_alert":
        title = "Drill: an exposure alert becomes a local lockdown"
        why = (
            "This is a fixture, not a dark-web crawl. "
            "Once data is out, the practical fix is to lock accounts, change passwords, and use a monitor you choose. "
            "DVielle did not crawl the dark web."
        )
    else:
        title = "A footprint item on this PC is ready for a fix"
        why = (
            "This ticket tracks a fix to done: local lockdown, an opt-in breach check, a do-it-yourself opt-out, "
            "or a partner you choose. DVielle did not search another person."
        )
    evidence = [
        f"Kind: {kind}",
        f"Label: {label}",
        "Scope: this machine's own exposure only.",
        "No email address is stored in this ticket.",
    ]
    if synthetic:
        evidence.append("Drill fixture. DVielle did not search the internet for this.")
    return Observation(
        pillar="footprint",
        kind=kind,
        subject_identity=subject,
        title_simple=title,
        why_it_matters=why,
        if_ignored="The item stays found until you pick a fix, mark it resolved, or leave it on the monitoring list.",
        evidence_refs=evidence,
        severity="medium",
        confidence="high" if kind in LOCAL_KINDS else "medium",
        recommended_action="Pick one resolution. DVielle will not search other people or claim the internet was erased.",
        resolution_steps=[
            "Start local lockdown, or open a partner playbook.",
            "Mark the ticket resolved only after you confirm the step, or leave it monitoring.",
        ],
        reversible="yes",
        identity_ok=True,
        expected=False,
        suspicious_mismatch=False,
        action_class="ask_user",
        signals={"target": "self", "synthetic": synthetic, "kind": kind, "label": label},
    )


def collect_footprint_facts() -> list[dict]:
    """No web search and no invented breach hits. Tickets are opened from explicit facts."""
    return []
