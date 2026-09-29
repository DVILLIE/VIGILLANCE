"""Local passkey guidance. This module does not change accounts.

WebAuthn Level 3 (W3C, https://www.w3.org/TR/webauthn-3/, reviewed 2026-09-29):
a public key credential is scoped to a relying party identifier. It can be
used only for that same RP. A lookalike origin cannot replay it.

What that ceremony does not cover, from the same claim brief:
session cookies and bearer tokens are a separate layer (W3C Device Bound
Session Credentials, https://www.w3.org/TR/dbsc/). Weak recovery such as SMS
or email alone can undo phishing resistance (FIDO Alliance account recovery
guidance). DVielle does not award a phishing-impossible badge and does not
drive a browser.
"""

from __future__ import annotations

from typing import Any

CHECKLIST = (
    {
        "id": "rp_passkey",
        "text": (
            "Where a site you use offers a passkey, adopt one there. "
            "DVielle does not sign you in and does not change that account."
        ),
    },
    {
        "id": "second_authenticator",
        "text": "Add another authenticator where that site allows it. One device is a single point of loss.",
    },
    {
        "id": "recovery",
        "text": (
            "Review account recovery. SMS or email alone can undo the phishing resistance "
            "of the sign-in ceremony."
        ),
    },
    {
        "id": "sessions",
        "text": (
            "When a site lets you sign out other sessions, that is a separate step. "
            "A passkey does not expire a stolen session cookie."
        ),
    },
)


def account_guidance() -> dict[str, Any]:
    """Education only. No badge, no browser, no account mutation."""
    return {
        "title": "Passkeys and account protection",
        "adopt": (
            "Adopt a passkey where the site (the relying party) already supports one. "
            "DVielle does not register it for you."
        ),
        "scope": (
            "A WebAuthn credential is scoped to that relying party. "
            "A lookalike site cannot use the credential registered for the real site. "
            "That is phishing resistance for the sign-in ceremony, not a promise about everything after it."
        ),
        "limits": [
            "Session cookies and bearer tokens after sign-in are a separate layer. Passkeys do not stop session theft.",
            "A weak recovery path (SMS or email alone) can undo phishing resistance. Prefer more than one authenticator.",
        ],
        "checklist": [dict(item) for item in CHECKLIST],
        "phishing_impossible": False,
        "badge": None,
        "browser_automation": False,
        "accounts_changed": False,
        "sources": [
            "https://www.w3.org/TR/webauthn-3/",
            "https://www.w3.org/TR/dbsc/",
            "https://fidoalliance.org/wp-content/uploads/2019/02/FIDO_Account_Recovery_Best_Practices-1.pdf",
        ],
    }


def review_marks(marks: dict | None) -> dict[str, Any]:
    """Record that the user said they reviewed a step. That does not change an account."""
    given = marks if isinstance(marks, dict) else {}
    items = []
    for row in CHECKLIST:
        items.append({**row, "reviewed": given.get(row["id"]) is True})
    reviewed = sum(1 for item in items if item["reviewed"])
    return {
        "items": items,
        "reviewed_count": reviewed,
        "phishing_impossible": False,
        "badge": None,
        "browser_automation": False,
        "accounts_changed": False,
        "meaning": (
            "Reviewed means you said you looked at that step. "
            "It does not change an account and it is not a protection badge."
        ),
    }
