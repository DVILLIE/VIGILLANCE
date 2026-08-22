"""Free web lookup for voice queries only (DuckDuckGo, no API key)."""

from __future__ import annotations

import logging
import re
import urllib.parse
import urllib.request

logger = logging.getLogger("dvielle.chat.web")

_WEB_HINTS = re.compile(
    r"\b(what is|who is|when is|where is|how to|latest|news|weather|today|"
    r"define|meaning of|price of|stock|score|release date|current)\b",
    re.I,
)


def needs_web_search(question: str) -> bool:
    q = question.strip().lower()
    if len(q) < 4:
        return False
    if _WEB_HINTS.search(q):
        return True
    # Short factual questions often need the web
    return q.endswith("?") and not _looks_like_stats_question(q)


def _looks_like_stats_question(q: str) -> bool:
    keys = (
        "cpu", "ram", "memory", "disk", "vpn", "ip", "dns", "gateway",
        "stats", "screen", "computer", "pc", "agent", "vigilance", "dvielle",
    )
    return any(k in q for k in keys)


def search_web(query: str, max_results: int = 3) -> str:
    """Return a short text summary from DuckDuckGo (free, no key)."""
    try:
        from duckduckgo_search import DDGS

        snippets: list[str] = []
        with DDGS() as ddgs:
            for row in ddgs.text(query, max_results=max_results):
                body = (row.get("body") or "").strip()
                title = (row.get("title") or "").strip()
                if body:
                    snippets.append(f"{title}: {body}" if title else body)
        if snippets:
            return "\n".join(snippets[:max_results])
    except Exception as exc:
        logger.warning("duckduckgo_search failed: %s", exc)

    return _search_ddg_instant(query)


def _search_ddg_instant(query: str) -> str:
    try:
        url = (
            "https://api.duckduckgo.com/?"
            + urllib.parse.urlencode({"q": query, "format": "json", "no_html": 1, "skip_disambig": 1})
        )
        with urllib.request.urlopen(url, timeout=8) as resp:
            import json

            data = json.loads(resp.read().decode("utf-8"))
        parts: list[str] = []
        if data.get("AbstractText"):
            parts.append(str(data["AbstractText"]))
        for topic in (data.get("RelatedTopics") or [])[:3]:
            if isinstance(topic, dict) and topic.get("Text"):
                parts.append(str(topic["Text"]))
        return "\n".join(parts) if parts else ""
    except Exception as exc:
        logger.warning("DDG instant API failed: %s", exc)
        return ""
