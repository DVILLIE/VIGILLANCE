"""Single runtime version resolver for DVielle / VIGILLANCE.

Authoritative packaging version lives in ``pyproject.toml`` ``[project].version``.
Installer DisplayVersion must read that same field.

Resolution order (so a stale editable/install cannot pin an old version forever):
1. ``pyproject.toml`` beside the repo root (source of truth in this tree)
2. ``importlib.metadata.version("dvielle")`` when installed without a local pyproject
3. Fallback constant (keep aligned when bumping)
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

# Keep aligned with pyproject.toml [project].version
_FALLBACK = "1.7.0"


def _from_pyproject(root: Path) -> str | None:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return None
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else None


@lru_cache(maxsize=1)
def get_version() -> str:
    root = Path(__file__).resolve().parents[1]
    from_file = _from_pyproject(root)
    if from_file:
        return from_file

    try:
        from importlib.metadata import version

        return version("dvielle")
    except Exception:
        pass

    return _FALLBACK
