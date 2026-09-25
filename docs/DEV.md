# Exercising an options decision locally

The shared engine lives in `agent/engine/`. Safety, Speed, and Storage feed it. A choice is stored under `data/learn/keep_on.txt` (and the matching pillar file). The desktop Smart Close dialog calls `choose_for_app_group`; it does not close an app until the user picks **Yes, close it**.

## Drill that does not touch this machine

```bash
python -m agent.exercise
```

That command uses a throwaway folder, a fake process closer, and a sandbox temp directory. It prints seven steps:

1. A first-seen CPU/RAM hog opens a ticket and closes nothing.
2. Calling mutate with no selected option is refused.
3. **Keep on** is written to keep-on memory.
4. The same app, still matching, stays quiet.
5. A suspicious mismatch opens a ticket again.
6. **Preview** lists temp files and deletes nothing.
7. **Free safe temp space now** removes the unlocked sandbox file and leaves the locked one.

Unit coverage for the same rules is `tests/test_keep_on_engine.py`:

```bash
python -m pytest tests/test_keep_on_engine.py -q
```

## What this slice does

- Quiet only when keep-on is `allow` and the subject still matches (`allowed_and_expected`). Storage cleanup is never quiet via allow.
- `never_warn` stays quiet until `suspicious_mismatch`.
- `deny`, `ask_always`, and unknown subjects open a ticket with `options[]`.
- A mutation runs only after a selected option (or the published Auto-protect set when `data/learn/auto_protect.txt` contains `enabled=true`).
- Disk monitor cycles no longer delete temp files, even if `enable_disk_cleanup` is on.
- Turning protection on reports that this version did not change it. Resolved is used only when a mutation actually happened.
- First Windows startup sighting seeds `baseline_safety.txt`. That file is not a user allow. A later path change on the same startup name is a mismatch.

## Deferred

- Privacy, AI data, footprint, and camera collectors are catalog stubs only.
- No real firewall or Defender toggle.
- Registry Run keys can be observed on Windows; disabling them is refused unless a user Startup-folder file is identified.
- Live speed identity from the advisor is the process name, not the exe path.
- Microsoft Guard auto-remediate and attack auto-block are still outside this options engine. Default `monitor_only` limits them.
- The Vite demo is not wired to the engine.
- Undo for a close or a renamed startup file is not stored yet.
- There is no `twin.json` owner profile.
- Distribution models in the spec are unchanged.
