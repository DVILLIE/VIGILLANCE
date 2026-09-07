"""Launch DVielle — GUI by default, headless with --headless."""

import sys
from pathlib import Path


def main() -> int:
    if "--headless" in sys.argv:
        sys.argv = [a for a in sys.argv if a != "--headless"]
        from agent.main import main as agent_main
        return agent_main()

    # Before any Tk window: claim a stable Windows AppUserModelID so the
    # taskbar/tray use DVielle's icon, not python.exe's.
    from dvielle.brand import configure_windows_app_identity

    configure_windows_app_identity()

    config_dir = None
    for i, arg in enumerate(sys.argv):
        if arg == "--config-dir" and i + 1 < len(sys.argv):
            config_dir = Path(sys.argv[i + 1])

    from dvielle.gui.app import main as gui_main
    return gui_main(config_dir=config_dir)


if __name__ == "__main__":
    raise SystemExit(main())
