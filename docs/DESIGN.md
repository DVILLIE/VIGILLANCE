# VIGILLANCE Design System

**Product:** DVielle / VIGILLANCE Mission Console  
**Date:** 2026-08-24  
**Aesthetic name:** **Phosphor Void**  
**Mood reference:** `assets/` brand radar mark + generated mood (`vigillance-design-mood.png` in Cursor assets)

---

## Design thesis

The interface is a **mission console for a living machine**, not a SaaS dashboard and not a neon “hacker” costume.

- One composition per viewport  
- Brand mark is a hero signal (radar DV), not a favicon afterthought  
- Type does the hierarchy; chrome stays almost invisible  
- Motion only for state change (pressure, workload shift, decision)  
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

## Layout grammar

1. **NOW strip** (full bleed top): brand mark + one sentence + workload pill  
2. **Pressure field**: 3–4 large meters (not 12 widgets)  
3. **Secondary rail**: Traffic / Surface tabs — one job  
4. **Why drawer**: evidence chain, not a chat wall  

Spacing scale: 8 / 12 / 16 / 24 / 40  
Radius: 0–6px max (architectural, not bubbly)  
Borders: 1px `stroke` only when structure needs it  

---

## Motion (2–3 intentional)

1. **Phosphor pulse** on workload/heartbeat (subtle opacity, ≤0.6s loop when live)  
2. **Pressure meter ease** when vector changes  
3. **Why drawer** slide 200ms ease-out  

No parallax, no particle storms, no endless ring spin as decoration (radar mark may animate *slowly* if present).

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
- [ ] One accent color dominates  
- [ ] Body ≥15px  
- [ ] No purple gradient skin  
- [ ] Mission sentence visible in NOW  
- [ ] Evidence “Why” reachable in ≤2 clicks  
