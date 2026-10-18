"""Explicit harmless desktop notification check; no visibility claim."""
import argparse
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.notifications import _deliver

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    errors = []
    class Capture(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.ERROR:
                errors.append(record.getMessage())
    handler = Capture()
    logger = logging.getLogger("dvielle")
    logger.addHandler(handler)
    started = time.monotonic()
    try:
        _deliver("D'Vielle integration check", "Notification backend check; no security settings changed.", 2)
    except Exception as exc:
        errors.append(str(exc))
    finally:
        logger.removeHandler(handler)
    result = {"native_backend_returned_without_error": not errors,
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "human_visibility_verified": False, "installed_runtime_changed": False,
              "errors": errors}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))
    return int(bool(errors))

if __name__ == "__main__":
    raise SystemExit(main())
