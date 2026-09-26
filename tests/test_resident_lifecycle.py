"""Real process lifecycle with all OS-mutating actions and heavy collectors off."""
import json
import subprocess
import sys
import time
from pathlib import Path

from agent.runtime import COLLECTOR_NAMES
from agent.controller import AgentController


def _config(tmp_path):
    import yaml
    path = tmp_path / 'config'
    path.mkdir()
    (path / 'config.yaml').write_text(yaml.safe_dump({
        'agent': {'data_dir': str(tmp_path / 'data'), 'process_priority': 'normal'},
        'modes': {'monitor_only': True, 'enable_toasts': False},
        'modules': {name: False for name in COLLECTOR_NAMES},
        'nerve': {'heartbeat_seconds': 1, 'pulse_seconds': 60, 'idle_deep_seconds': 900},
    }), encoding='utf-8')
    (path / 'whitelists.yaml').write_text('{}', encoding='utf-8')
    return path


def test_real_resident_single_owner_snapshot_and_graceful_stop(tmp_path):
    config = _config(tmp_path)
    cmd = [sys.executable, '-m', 'agent.main', '--config-dir', str(config)]
    owner = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    snapshot = tmp_path / 'data' / 'twin.json'
    follower = AgentController(config_dir=config)
    try:
        deadline = time.monotonic() + 15
        data = {}
        while time.monotonic() < deadline and owner.poll() is None:
            try:
                data = json.loads(snapshot.read_text(encoding='utf-8'))
                if data.get('runtime', {}).get('state') == 'running':
                    break
            except (OSError, ValueError):
                pass
            time.sleep(.1)
        assert data.get('runtime', {}).get('state') == 'running', (
            owner.stderr.read() if owner.poll() is not None else 'Owner did not publish a heartbeat within 15 seconds')
        token = data['runtime']['owner_token']
        assert data['memory']['total_phys_bytes'] > 0
        duplicate = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        assert duplicate.returncode == 0
        assert 'already running' in duplicate.stdout
        assert json.loads(snapshot.read_text())['runtime']['owner_token'] == token
        follower.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and follower.status.ownership != 'attached':
            time.sleep(.1)
        assert follower.status.ownership == 'attached'
        assert follower.status.running
        assert follower.twin.as_dict()['runtime']['owner_token'] == token
        follower.stop()
        follower._thread.join(timeout=5)
        assert not follower._thread.is_alive()
        assert owner.poll() is None  # disconnect never stops the external owner
        follower.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and follower.status.ownership != 'attached':
            time.sleep(.1)
        assert follower.status.ownership == 'attached'
        stop = subprocess.run(cmd + ['--stop'], capture_output=True, text=True, timeout=15)
        assert stop.returncode == 0, stop.stderr
        assert owner.wait(timeout=10) == 0
        assert json.loads(snapshot.read_text())['runtime']['state'] == 'stopped'
        follower._thread.join(timeout=6)
        assert not follower._thread.is_alive()  # intentional stop must not trigger takeover
        assert json.loads(snapshot.read_text())['runtime']['owner_token'] == token
    finally:
        follower.stop()
        if owner.poll() is None:
            owner.terminate()
        owner.communicate(timeout=10)
