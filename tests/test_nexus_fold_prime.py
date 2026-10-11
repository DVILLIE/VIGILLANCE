"""Real Tk widget checks and isolated preference tests; no agent actions are run."""
import time

import pytest

from dvielle.gui import theme as T
from dvielle.gui.motion import Motion
from dvielle.gui.theme_store import load_appearance, load_motion, save_appearance, save_motion


def test_motion_and_appearance_preserve_each_other(tmp_path):
    save_motion(tmp_path, False)
    save_appearance(tmp_path, "light")
    assert load_motion(tmp_path) is False
    assert load_appearance(tmp_path) == "light"
    save_motion(tmp_path, True)
    assert load_appearance(tmp_path) == "light"
    assert load_motion(tmp_path) is True


@pytest.fixture(scope="module")
def console(tmp_path_factory):
    import queue
    import customtkinter as ctk
    from dvielle.gui.app import DVielleApp
    T.install_day()
    T.apply("dark")
    try:
        root = ctk.CTk()
    except Exception as exc:
        pytest.skip(f"Tk unavailable: {exc}")
    root.withdraw()
    root.geometry("1180x780+20+20")
    root.configure(fg_color=T.BG_DARK)
    errors = []
    root.report_callback_exception = lambda *args: errors.append(args)
    # Build the production UI only. No controller, collectors, close action, or tray starts.
    app = DVielleApp.__new__(DVielleApp)
    app.root = root
    app.motion = Motion(root, True)
    app._active_page = None
    app.data_dir = tmp_path_factory.mktemp("console-assessment")
    app._ui_events = queue.Queue()
    try:
        app._build_ui()
    except Exception:
        root.destroy()
        raise
    root.deiconify()
    root.update()
    yield app, errors
    app.assessment_workspace.close()
    app.motion.close()
    root.destroy()
    T.apply("dark")


def pump(root, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        root.update()
        time.sleep(.01)


def test_corrupt_assessment_ledger_keeps_workspace_and_console_available(console, tmp_path):
    from dvielle.gui.assessment import AssessmentWorkspace
    app, errors = console
    directory = tmp_path / "assessment-corruption"
    directory.mkdir()
    ledger = directory / "assessments.db"
    ledger.write_bytes(b"invalid SQLite ledger; retain for review")
    workspace = AssessmentWorkspace(app.root, directory, app._ui_events.put)
    try:
        assert workspace.engine is None
        assert workspace.local_button.cget("state") == "disabled"
        workspace.start_local()
        assert workspace.worker is None
        assert "No assessment started" in workspace.status.cget("text")
        assert ledger.read_bytes() == b"invalid SQLite ledger; retain for review"
        app.root.update()
        assert not errors
    finally:
        workspace.close()
        workspace.destroy()


def test_navigation_and_theme_keep_all_pages_accessible(console):
    app, errors = console
    for mode in ("dark", "light"):
        T.apply(mode)
        for key in app._pages:
            app._nav_buttons[key].invoke()
            pump(app.root, .34)
            assert app._pages[key].winfo_viewable()
            assert app._pages[key].winfo_manager() == "canvas"
            assert sum(bool(page.winfo_viewable()) for page in app._pages.values()) == 1
            assert app._nav_buttons[key].winfo_ismapped()
        assert app.nav.winfo_width() <= app.root.winfo_width()
    assert not errors


def test_motion_off_and_hidden_stop_logo_and_transitions(console):
    app, errors = console
    pump(app.root, .6)
    initial_index = app.logo._idle_i
    initial_lights = app.logo._current.tobytes()
    pump(app.root, .4)
    assert app.logo._idle_i > initial_index
    assert app.logo._current.tobytes() != initial_lights
    app.motion.set_enabled(False)
    app.logo.set_motion_enabled(False)
    frozen = app.logo._current.tobytes()
    index = app.logo._idle_i
    pump(app.root, .25)
    assert app.logo._current.tobytes() == frozen
    assert app.logo._idle_i == index
    assert app.logo._job is None
    values = []
    app.motion.tween("check", values.append)
    assert values == [1.0]
    assert app.motion._job is None
    app.logo.set_motion_enabled(True)
    app.motion.set_enabled(True)
    app.motion.tween("hide-check", lambda amount: None)
    app.root.withdraw()
    pump(app.root, .2)
    assert app.logo._job is None
    assert app.motion._job is None
    assert not app.motion._items
    app.root.deiconify()
    pump(app.root, .3)
    assert app.logo._job is not None
    assert not errors


def test_device_links_tremble_and_stop_when_hidden(console):
    app, errors = console
    app._show_page("now")
    app.motion.set_enabled(True)
    pump(app.root, .25)
    stage = app.link_map
    items = stage.canvas.find_withtag("link_vibration")
    assert len(items) == 12
    first = stage.canvas.coords(items[0])
    pump(app.root, .2)
    assert stage.canvas.coords(stage.canvas.find_withtag("link_vibration")[0]) != first
    assert len(stage.canvas.find_withtag("link_vibration")) == 12
    app.motion.set_enabled(False)
    pump(app.root, .25)
    assert not stage.canvas.find_withtag("link_vibration")
    app.motion.set_enabled(True)
    app.root.withdraw()
    pump(app.root, .1)
    assert stage._vibration_job is None
    app.root.deiconify()
    pump(app.root, .2)
    assert stage._vibration_job is not None
    assert app.logo.size == 148
    assert "Vigilia — Always Watching." in app.brand_tagline.cget("text")
    assert not errors


def test_unavailable_readings_are_not_zero_or_healthy(console):
    app, errors = console
    app.now_cpu.set_value(None)
    assert app.now_cpu.value.cget("text") == "—"
    assert app.now_cpu.detail.cget("text") == "Waiting for readings"
    assert all(value == "Unknown" for _, value, _ in app.link_map.nodes)
    assert "Unknown" in app.prime_protection.cget("text")
    app.now_cpu.set_value(0)
    assert app.now_cpu.value.cget("text") == "0%"
    assert not errors


def test_controls_fit_and_capture_actual_windows_when_requested(console):
    import os
    from pathlib import Path
    app, errors = console
    app.now_cpu.set_value(None)
    app._show_page("now")
    capture = os.environ.get("DVIELLE_CAPTURE_THEME")
    for mode, size in (("dark", "1440x940"), ("light", "1180x780")):
        T.apply(mode)
        app.root.geometry(size+"+10+10")
        app.root.title("DVielle — Nexus Fold Prime | UI verification, monitoring not started")
        app.root.lift()
        pump(app.root, .5)
        edge = app.root.winfo_rootx()+app.root.winfo_width()
        assert app._pages["now"].winfo_width() >= app.stage.winfo_width()-50
        assert app.motion_btn.winfo_rootx()+app.motion_btn.winfo_width() <= edge
        for button in app._nav_buttons.values():
            assert button.winfo_rootx()+button.winfo_width() <= edge
        for tile in (app.now_cpu, app.now_mem, app.now_disk):
            assert tile.winfo_rootx()+tile.winfo_width() <= tile.master.winfo_rootx()+tile.master.winfo_width()+1
        if capture:
            import ctypes
            from PIL import ImageGrab
            hwnd = ctypes.windll.user32.GetAncestor(app.root.winfo_id(), 2)
            directory = Path(capture)
            directory.mkdir(parents=True, exist_ok=True)
            ImageGrab.grab(window=hwnd).save(directory / f"nexus-fold-prime-{mode}.png")
    assert not errors


def test_privacy_policy_and_preview_fit_real_workspace(console):
    from agent.assessment.history import HistoryPrivacy
    app, errors = console
    app._show_page('ethical') if 'ethical' in app._pages else app._show_page('assessment')
    workspace = app.assessment_workspace
    workspace.tabs.set('Privacy & costs')
    workspace.retention_enabled.deselect()
    workspace.save_history_policy()
    assert HistoryPrivacy(workspace.engine).policy()['enabled'] is False
    workspace.preview_history_cleanup()
    assert workspace.cleanup_preview is not None
    pump(app.root, .15)
    assert workspace.retention_runs.winfo_rootx() + workspace.retention_runs.winfo_width() <= app.root.winfo_rootx() + app.root.winfo_width()
    assert not errors


def test_readiness_button_reads_actual_service_without_assessment(console):
    import queue
    app, errors = console
    workspace = app.assessment_workspace
    workspace.start_readiness()
    # Readiness may inventory thousands of protected runtime files. Keep a
    # bounded wait without assuming an eight-second disk/SCM response.
    workspace.worker.join(timeout=30)
    assert not workspace.worker.is_alive()
    while True:
        try:
            callback = app._ui_events.get_nowait()
        except queue.Empty:
            break
        callback()
    pump(app.root, .1)
    assert workspace.current_report is None
    assert 'Service readiness observed:' in workspace.status.cget('text')
    assert 'No system changes performed.' in workspace.status.cget('text')
    assert not errors
