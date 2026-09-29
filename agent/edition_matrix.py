"""Edition-honest Windows prevention matrix.

SKU support is not an enabled-state claim and not a sandbox, camera, or
footprint observation. The 2026-09-29 primary-source brief is the authority
for which editions Microsoft documents. This module does not mutate Defender,
firewall rules, or App Control policy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

CapState = Literal["AVAILABLE", "LIMITED", "UNKNOWN", "UNAVAILABLE"]
Sku = Literal["Home", "ProOrHigher", "Server", "Unknown", "NonWindows"]

FEATURE_ORDER: tuple[str, ...] = (
    "asr",
    "cfa",
    "firewall",
    "smart_app_control",
    "windows_sandbox",
    "app_control_authoring",
)

PRODUCT_NOTES: tuple[str, ...] = (
    "DVielle orchestrates Microsoft Defender. It does not replace Defender or disable real-time protection.",
    "Cells describe edition support, not whether the feature is turned on.",
    "CFA is documented to control unauthorized modification. DVielle does not claim CFA prevents reading or exfiltration.",
    "Windows Sandbox is not supported on Windows Home.",
    "Sandbox AVAILABLE means the client SKU supports Windows Sandbox. It does not mean the optional feature is installed or that a sandbox is running. Default sandbox networking is on.",
    "App Control for Business PowerShell authoring is not available on Home. A policy can still be effective on Home if one was deployed another way.",
    "Smart App Control is probe-only. Clean-install eligibility, region limits, and toggle reversibility without reset are not inferred.",
    "Windows Defender Application Guard is deprecated and is not a Home sandbox substitute. Client Hyper-V is not available on Home.",
    "This matrix does not enforce ASR, CFA, or App Control. Support is not an on/off reading.",
)

ASSUMPTIONS: tuple[str, ...] = (
    "Edition support follows the Microsoft Learn matrices locked in docs/FUNCTION_SPEC.md on 2026-09-29.",
    "Home is a client Home SKU (EditionID Core*). ProOrHigher is client Professional, Enterprise, or Education.",
    "Server is not given a Windows Sandbox claim. Server App Control authoring is outside the locked client matrix and stays UNKNOWN.",
    "ASR and CFA support assumes the Windows edition includes Microsoft Defender Antivirus. Enabled state is a separate observation.",
    "A Smart App Control DWORD is an observed policy state, not proof the device is eligible to turn Smart App Control back on.",
)


def classify_sku(edition_id: str | None, caption: str | None, *, windows: bool) -> Sku:
    """Classify a SKU from EditionID, then from an OS caption. Unknown stays unknown."""
    if not windows:
        return "NonWindows"
    token = (edition_id or "").strip().lower()
    if token.startswith("core"):
        return "Home"
    if token.startswith("server"):
        return "Server"
    if token.startswith(("professional", "enterprise", "education", "iotenterprise", "cloudedition")):
        return "ProOrHigher"
    text = (caption or "").lower()
    if "server" in text:
        return "Server"
    if "home" in text and "pro" not in text:
        return "Home"
    if any(word in text for word in ("pro", "enterprise", "education")):
        return "ProOrHigher"
    return "Unknown"


def interpret_sac(value: int | None, *, readable: bool, windows: bool) -> tuple[str | None, CapState]:
    """Map VerifiedAndReputablePolicyState. Learn: 0 Off, 1 Enforce, 2 Evaluation.

    A successful read means the probe ran. It does not prove clean-install eligibility.
    """
    if not windows:
        return None, "UNAVAILABLE"
    if not readable or not isinstance(value, int) or isinstance(value, bool):
        return None, "UNKNOWN"
    if value == 0:
        return "off", "LIMITED"
    if value == 1:
        return "enforcement", "AVAILABLE"
    if value == 2:
        return "evaluation", "LIMITED"
    return None, "UNKNOWN"


def _features(sku: Sku, smart_app_control: CapState) -> dict[str, CapState]:
    if sku == "NonWindows":
        return {name: "UNAVAILABLE" for name in FEATURE_ORDER}
    if sku == "Home":
        sandbox: CapState = "UNAVAILABLE"
        authoring: CapState = "UNAVAILABLE"
    elif sku == "ProOrHigher":
        sandbox = "AVAILABLE"
        authoring = "AVAILABLE"
    elif sku == "Server":
        sandbox = "UNAVAILABLE"
        authoring = "UNKNOWN"
    else:
        sandbox = "UNKNOWN"
        authoring = "UNKNOWN"
    return {
        "asr": "AVAILABLE",
        "cfa": "AVAILABLE",
        "firewall": "AVAILABLE",
        "smart_app_control": smart_app_control,
        "windows_sandbox": sandbox,
        "app_control_authoring": authoring,
    }


@dataclass
class EditionMatrix:
    sku: Sku
    edition_id: str | None = None
    features: dict[str, CapState] = field(default_factory=dict)
    smart_app_control_mode: str | None = None
    notes: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_edition_matrix(
    sku: Sku,
    *,
    edition_id: str | None = None,
    smart_app_control: CapState = "UNKNOWN",
    smart_app_control_mode: str | None = None,
) -> EditionMatrix:
    """Build the locked matrix. Home never reports Windows Sandbox as available."""
    if sku == "NonWindows":
        smart_app_control = "UNAVAILABLE"
        smart_app_control_mode = None
    elif smart_app_control not in {"AVAILABLE", "LIMITED", "UNKNOWN", "UNAVAILABLE"}:
        smart_app_control = "UNKNOWN"
        smart_app_control_mode = None
    features = _features(sku, smart_app_control)
    if sku == "Home":
        features["windows_sandbox"] = "UNAVAILABLE"
        features["app_control_authoring"] = "UNAVAILABLE"
    return EditionMatrix(
        sku=sku,
        edition_id=edition_id,
        features=features,
        smart_app_control_mode=smart_app_control_mode,
        notes=list(PRODUCT_NOTES),
        assumptions=list(ASSUMPTIONS),
    )
