# Exercising an options decision locally

The shared engine lives in `agent/engine/`. Safety, Speed, and Storage feed it. A choice is stored under `data/learn/keep_on.txt` (and the matching pillar file). The desktop Smart Close dialog calls `choose_for_app_group`; it does not close an app until the user picks **Yes, close it**.

## Drill that does not touch this machine

```bash
python -m agent.exercise
```

That command uses a throwaway folder, a fake process closer, a fake per-app blocker, and a sandbox temp directory. It prints the speed and storage steps, then privacy, AI, and camera:

1. A first-seen CPU/RAM hog opens a ticket and closes nothing.
2. Calling mutate with no selected option is refused.
3. **Keep on** is written to keep-on memory.
4. The same app, still matching, stays quiet.
5. A suspicious mismatch opens a ticket again.
6. **Preview** lists temp files and deletes nothing.
7. **Free safe temp space now** removes the unlocked sandbox file and leaves the locked one.
8. A first-seen app talking to the internet opens a privacy ticket and blocks nothing.
9. Mutate without a privacy choice is refused.
10. **Allow this app's internet** stays quiet while that app is still open.
11. The same name while the app is not open is a suspicious mismatch, and still blocks nothing.
12. An AI connection named while that app is closed opens a ticket and does not claim a model was trained.
13. **Block this AI app's internet** while the process is already gone does not block, and does not say traffic stopped.
14. An allowed camera app that is actually open (Zoom in the drill) stays quiet and is not closed.
15. Camera use named as Zoom while Zoom is not open opens a ticket and does not close anything.
16. **Stop this app's camera use** runs only after that choice, and only for the app you picked.
17. **Turn camera off in system settings** asks for the settings page and does not turn the camera off or store a picture.
18. A footprint ticket lists lockdown, opt-in breach check, DIY opt-out, partner playbooks, mark resolved, and still monitoring.
19. The breach check is refused until you choose it. With no email enrolled, nothing is sent.
20. An opt-in drill check says the email leaves the device, stores no address, and does not claim the internet was erased.
21. Partner names (DeleteMe, Incogni, Aura, LifeLock, REMOVE) are links in the playbook. None is required, and none is called.
22. **Mark resolved** records your confirmation. The progress file is `data/learn/baseline_footprint.txt`.

Unit coverage is `tests/test_keep_on_engine.py`, `tests/test_privacy_ai_camera.py`, and `tests/test_footprint.py`:

```bash
python -m pytest tests/test_keep_on_engine.py tests/test_privacy_ai_camera.py tests/test_footprint.py -q
```

## What this slice does

- Quiet only when keep-on is `allow` and the subject still matches (`allowed_and_expected`). Storage cleanup is never quiet via allow.
- `never_warn` stays quiet until `suspicious_mismatch`.
- `deny`, `ask_always`, and unknown subjects open a ticket with `options[]`.
- A mutation runs only after a selected option (or the published Auto-protect set when `data/learn/auto_protect.txt` contains `enabled=true`).
- Disk monitor cycles no longer delete temp files, even if `enable_disk_cleanup` is on.
- Turning protection on reports that this version did not change it. Resolved is used only when a mutation actually happened.
- First Windows startup sighting seeds `baseline_safety.txt`. That file is not a user allow. A later path change on the same startup name is a mismatch.

## Privacy, AI, and Camera

The same engine evaluates them. Live egress uses established public connections (`agent/modules/egress_watch.py`) and skips LAN, browsers, system processes, and Windows Update hosts. An AI fact needs a known AI hostname or a known AI app name plus a public connection. The live cycle tries at most eight reverse lookups; if a lookup fails, that IP is not labeled as an AI vendor. Camera holders on Linux are process links to `/dev/video*` (`agent/modules/camera_guard.py`). The device is not opened and no frame is stored. Windows and macOS camera in-use checks return “unknown” rather than a fake “camera off.”

Blocking an app’s network and stopping camera use are options-only. Auto-protect does not do either. There is no per-app firewall helper on Linux, so the default block says traffic was not stopped. The inbound `scripts/block-ip.ps1` rule is not used for this.

## Footprint Resolution Center

Every footprint item is a ticket on the same engine: found, in progress, resolved, or monitoring. Remote items (breach, public page, broker listing, dark-web style alert) open only from an explicit synthetic fixture or a future confirmed source. The live collector does not search the web and does not invent a breach. An opt-in breach check says the email leaves the device; with no checker connected, nothing is sent, and the address is not written to the ticket or `baseline_footprint.txt`. Partner rows are playbook links, not accounts.

## Deferred

- No real firewall or Defender toggle.
- No live Have I Been Pwned call and no partner API enrollment. Those stay opt-in hooks.
- Registry Run keys can be observed on Windows; disabling them is refused unless a user Startup-folder file is identified.
- Live speed identity from the advisor is the process name, not the exe path.
- Microsoft Guard auto-remediate and attack auto-block are still outside this options engine. Default `monitor_only` limits them.
- The Vite demo is not wired to the engine.
- Undo for a close or a renamed startup file is not stored yet.
- There is no `twin.json` owner profile.
- Distribution models in the spec are unchanged.
