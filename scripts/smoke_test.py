#!/usr/bin/env python3
"""DVielle smoke test — run after install or in CI."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(name: str, fn) -> None:
    try:
        fn()
        print(f"  PASS  {name}")
    except Exception as exc:
        FAILURES.append(f"{name}: {exc}")
        print(f"  FAIL  {name}: {exc}")


def main() -> int:
    print("")
    print("  DVIELLE SMOKE TEST")
    print("  ==================")
    print(f"  Root: {ROOT}")
    print("")

    check("import dvielle", lambda: importlib.import_module("dvielle"))
    check("import agent.main", lambda: importlib.import_module("agent.main"))
    check("import agent.controller", lambda: importlib.import_module("agent.controller"))
    check("import agent.store.db", lambda: importlib.import_module("agent.store.db"))
    check("resource_advisor", lambda: importlib.import_module("agent.modules.resource_advisor"))
    check("microsoft_guard", lambda: importlib.import_module("agent.modules.microsoft_guard"))

    def _gui_imports():
        try:
            import tkinter  # noqa: F401
        except ImportError:
            raise RuntimeError("tkinter not available (install python3-tk on Linux)")
        import customtkinter  # noqa: F401
        importlib.import_module("dvielle.gui.hologram")
        importlib.import_module("dvielle.gui.voice")
        importlib.import_module("dvielle.gui.app")

    check("gui modules", _gui_imports)

    def _agent_once():
        from agent.main import main as agent_main
        rc = agent_main(["--once", "--config-dir", str(ROOT / "config")])
        if rc != 0:
            raise RuntimeError(f"agent --once returned {rc}")

    check("agent one cycle", _agent_once)

    def _closeable():
        from agent.modules.resource_advisor import get_closeable_processes
        get_closeable_processes(3)

    check("get_closeable_processes", _closeable)

    def _config():
        from agent.utils import load_yaml
        cfg = load_yaml(ROOT / "config" / "config.yaml")
        assert cfg.get("agent", {}).get("name") == "DVielle"

    check("config.yaml", _config)

    print("")
    if FAILURES:
        print(f"  FAILED ({len(FAILURES)} checks)")
        for f in FAILURES:
            print(f"    - {f}")
        return 1
    print("  ALL CHECKS PASSED")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
