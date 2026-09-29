#!/usr/bin/env python3
"""Non-collecting installation check; never starts the agent or reads host telemetry."""

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
    FAILURES.clear()
    print("")
    print("  DVIELLE SMOKE TEST")
    print("  ==================")
    print(f"  Root: {ROOT}")
    print("")

    def _python_version():
        if sys.version_info[:2] != (3, 12):
            raise RuntimeError("DVielle requires the vetted Python 3.12 runtime")

    check("Python 3.12", _python_version)

    check("import dvielle", lambda: importlib.import_module("dvielle"))
    check("import agent.main", lambda: importlib.import_module("agent.main"))
    check("import agent.controller", lambda: importlib.import_module("agent.controller"))
    check("import agent.store.db", lambda: importlib.import_module("agent.store.db"))
    check("resource_advisor", lambda: importlib.import_module("agent.modules.resource_advisor"))
    check("microsoft_guard", lambda: importlib.import_module("agent.modules.microsoft_guard"))
    check("defender_health", lambda: importlib.import_module("agent.modules.defender_health"))
    check("edition_matrix", lambda: importlib.import_module("agent.edition_matrix"))
    check("prevention", lambda: importlib.import_module("agent.modules.prevention"))
    check("prevention_apply", lambda: importlib.import_module("agent.modules.prevention_apply"))
    check("firewall_assist", lambda: importlib.import_module("agent.modules.firewall_assist"))
    check("privilege", lambda: importlib.import_module("agent.privilege"))
    check("cpu_contract", lambda: importlib.import_module("agent.cpu_contract"))
    check("sandbox", lambda: importlib.import_module("agent.modules.sandbox"))
    check("tuf", lambda: importlib.import_module("agent.update.tuf"))
    check("privilege_pipe", lambda: importlib.import_module("agent.privilege.pipe"))

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

    def _config():
        from agent.runtime import load_runtime_config
        cfg, _, _ = load_runtime_config(ROOT / "config")
        if cfg.get("agent", {}).get("name") != "DVielle":
            raise RuntimeError("config.yaml does not identify DVielle")

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
