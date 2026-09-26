# DVielle local snapshot viewer

The browser entry point reads a real `data/twin.json` selected by the user. Until a file is loaded, all metrics remain unavailable. Each value carries its source time; the heartbeat becomes stale as the imported file ages. Reload the file for newer evidence.

Run `Start-Demo.bat` on the same PC, then open `http://127.0.0.1:43123`. Use **Load agent snapshot** to select `C:\DVILLIE\data\twin.json`. The browser reads this file locally; it does not upload it. It cannot start the Windows agent, approve process termination, or modify the system. The native console provides those supported controls.

The entry point no longer imports the legacy simulation, chat, microphone, voice, or external-IP components. It makes no background model/search/IP requests. The development server listens only on loopback and has no search proxy. Legacy component source is retained for design reference, outside the running application.

Development: `npm ci`, then `npm test`, `npm run build` and `npm run lint`. Parser tests use isolated fixtures; they are not measurements from this PC. Node and dependency requirements are in `package.json` and the lockfile.
