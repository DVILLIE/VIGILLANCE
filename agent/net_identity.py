"""Hostname / domain identity helpers — boundary matching only (P0.4).

Never use substring allowlists for security policy.
"""

from __future__ import annotations

import ipaddress
import re


_DNS_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def normalize_hostname(value: str | None) -> str | None:
    if not value:
        return None
    h = value.strip().lower().rstrip(".")
    if not h or " " in h:
        return None
    # IP literals are not hostnames for domain allowlists
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    # Basic DNS shape (allow multi-label)
    labels = h.split(".")
    if any(not _DNS_LABEL.match(lab) for lab in labels if lab):
        return None
    if len(h) > 253:
        return None
    return h


def host_matches_domain(host: str | None, domain: str | None) -> bool:
    """Exact domain or subdomain: api.example.com matches example.com; badexample.com does not."""
    h = normalize_hostname(host)
    d = normalize_hostname(domain)
    if not h or not d:
        return False
    return h == d or h.endswith("." + d)


def host_matches_any(host: str | None, domains: set[str] | list[str]) -> bool:
    return any(host_matches_domain(host, d) for d in domains)


def looks_like_ipv4_or_ipv6(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False
