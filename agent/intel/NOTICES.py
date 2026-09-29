"""Write the checked-in intel notices beside a saved feed."""

from __future__ import annotations

from pathlib import Path

_NOTICE = Path(__file__).with_name("NOTICES.txt")


def write_notices(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "NOTICES.txt"
    target.write_text(_NOTICE.read_text(encoding="utf-8"), encoding="utf-8")
