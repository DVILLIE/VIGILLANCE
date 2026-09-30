# VIGILLANCE Design System

**Product:** DVielle / VIGILLANCE Mission Console  
**Date:** 2026-08-24  
**Aesthetic name:** **Phosphor Void**  
**Mood reference:** `assets/` brand radar mark and the generated mood image `vigillance-design-mood.png`

---

## Design thesis

The interface is a **mission console for a living machine**, not a SaaS dashboard and not a neon “hacker” costume.

- One composition per viewport  
- Brand mark is a hero signal (radar DV), not a favicon afterthought  
- Type does the hierarchy; chrome stays almost invisible  
- Motion is the logo only (a short rotate-in, then a slow pulse). Status changes by color and text, not by animation  
- Readable at a glance with glasses on (large type scale)

**Anti-patterns (banned):** purple-on-white gradients, cream+terracotta “AI default,” broadsheet newspaper UI, emoji icon rows, pill-stat strips, glassmorphism blobs, multi-layer shadows.

---

## Color — Phosphor Void

| Token | Hex | Role |
|-------|-----|------|
| `void` | `#070B12` | App background |
| `panel` | `#0C121C` | Primary surfaces |
| `panel-2` | `#111925` | Nested / inset |
| `stroke` | `#1E2A3A` | Hairlines only |
| `phosphor` | `#3DE8C8` | Primary accent / brand |
| `phosphor-dim` | `#1FAE96` | Hover / secondary accent |
| `phosphor-hot` | `#7DFFE8` | Focus / live pulse |
| `ink` | `#E7F2F0` | Primary text |
| `ink-mute` | `#7A8B99` | Secondary text |
| `ok` | `#3DFFB0` | Healthy / safe |
| `warn` | `#F0B429` | Caution / pressure |
| `crit` | `#FF4D6A` | Using / threat / fail |
| `policy-allow` | `#3DE8C8` | ALLOW |
| `policy-audit` | `#7A8B99` | AUDIT |
| `policy-restrict` | `#F0B429` | RESTRICT |
| `policy-block` | `#FF4D6A` | BLOCK |

Accent usage: **one phosphor voice**. Status colors appear only on state.

---

## Typography

Prefer licensed or system-available pairings:

| Role | Preferred | Fallback | Size guide |
|------|-----------|----------|------------|
| Display | **Syne** or **Space Grotesk** Bold | Segoe UI | 40–56 |
| Title | Space Grotesk SemiBold | Segoe UI Semibold | 20–24 |
| Body | **IBM Plex Sans** | Segoe UI | 15–16 |
| Mono / intel | **IBM Plex Mono** | Consolas | 14–15 |
| Micro | IBM Plex Sans | Segoe UI | 12–13 |

Rules:
- Display for product name / NOW headline only  
- Never shrink body below 15px in the shipped console  
- Mono for evidence, IPs, process trees  

---

## Layout grammar (2.4.0 Clear Deck)

The console is a shell, not a four-column instrument panel.

1. **Header** — logo, product name, one status sentence, the day's color name, Dark/Light, start.
2. **Left pages** — Now, This PC, Network, Findings, Protection, Apps. One page is visible.
3. **Now** — three still load rings (processor, memory, disk), a still network map, latest notes as cards (severity glyph, color bar, and a plain word: Noted, Caution, Needs a look, Settled), and collector chips. Page icons and a header status orb are drawn, not typed bullets. The header logo is the brand mark. There is no separate Watch card.
4. **This PC** — full-width load bars (processor, memory, disk).
5. **Apps** — noticed, you choose, then it can close. The choice dialogs are unchanged.
6. **Footer** — work log, why, attacks, pause, hide. Why stays one click away.

Spacing scale: 8 / 12 / 16 / 20 / 24  
Radius: 8–14 on cards. The header, rail, and footer stay square.  
Borders: 1px stroke on cards. Accent marks the selected page and healthy/pressure state.  

---

## Motion (2.4.0)

Only the brand mark animates.

1. **Logo** — a short rotate-in when the console opens, then a slow brightness pulse (about once a second). That is the only motion.
2. **Clock** — the local/UTC digits update once a second. The label does not move.
3. **Measurements** — gauges, collector chips, and the findings log update when new observations arrive. They do not ease, sweep, or blink.

No parallax, no particle storms, no scan line, no pulsing status dot, no animated tabs or buttons.

The day's accent is chosen once, from the local date, when the console opens. Orbits, the second color, and card-corner marks use that seed and stay still. Dark and Light remain the saved choice in `console_ui.json`. The five day names are Violet, Coral, Gold, Sky, and Rose. On Light those hues are cooled (soft sky, mint, lilac, dusty rose) so they do not glare on white. Dark keeps the richer pair. Green, amber, and red stay the status colors.

The header mark is a drawn D/V orbital emblem. It scales and turns in, the orbits complete during that short intro, then the whole mark brightens slightly about once a second. That is the only motion.

## Light palette — Dayglass

Dark above remains the default. Light is optional and stored locally.

| Token | Hex | Role |
|-------|-----|------|
| `void` | `#F4F7FA` | Cool paper |
| `panel` | `#FFFFFF` | Primary surfaces |
| `panel-2` | `#E8EEF4` | Nested / inset |
| `stroke` | `#D2DCE6` | Hairlines |
| `phosphor` | day's cool accent | Calm sky, mint, or lilac. No neon on white |
| `ink` | `#1A2733` | Primary text |
| `ink-mute` | `#526070` | Secondary text |
| `ok` / `warn` / `crit` | `#0C7040` / `#8A5600` / `#B4233A` | Status only |

Persistence: `<data_dir>/console_ui.json`, key `appearance`, values `dark` or `light`. Missing or invalid file means dark. CustomTkinter color arguments are `(light, dark)` tuples so a switch repaints widgets. Tk canvases redraw from the active hex. `system` appearance mode is not used: on Linux, CustomTkinter documents that system mode stays light.

---

## Iconography & brand

- Primary brand: radar **DV** mark (`assets/brand/dvielle_logo.png` / `.ico`)  
- Prefer geometric line icons (stroke 1.5) over filled skeuomorphism  
- No emoji in chrome  

---

## Component recipes

| Component | Spec |
|-----------|------|
| Primary button | `phosphor` fill, `void` text, height ≥40 |
| Danger confirm | `crit` fill, explicit label (“Yes, close it”) |
| Policy chip | ALLOW/AUDIT/RESTRICT/BLOCK with token colors |
| Evidence card | mono body, timestamp, score, confidence |
| Smart Close row | SAFE=`ok` · LINKED=`warn` · USING=`crit` |

---

## Mapping to current CustomTkinter theme

Evolve `dvielle/gui/theme.py` toward Phosphor Void tokens and the large type scale already started. Full Syne/Plex embedding can land when packaging fonts with the installer; until then use Segoe/Consolas with the **sizes and colors** in this file.

---

## Design QA checklist

- [ ] First viewport readable as VIGILLANCE without reading nav  
- [ ] The day's accent plus one orbit color, status colors unchanged  
- [ ] Body ≥15px  
- [ ] Orbits and field marks are still. Only the logo moves  
- [ ] Mission sentence visible in NOW  
- [ ] Evidence “Why” reachable in ≤2 clicks  
