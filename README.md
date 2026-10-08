# CTI Casefile 004 — The Turned-Off Alarm

A single-page, browser-based **cyber threat intelligence investigation simulator**,
built from the scenario spec in `new.scenario`.

You are a Tier 1 escalation analyst. Three alerts fired on one workstation and nobody
has told you which of them matter. You get the raw event stream, three alerts, an
account record and a change calendar for the estate. You have to work out what
actually happened, prove it, name it, and write an assessment someone else can act on.

One case, six stages, 100 XP, about 25 minutes.

**No account. No setup. No terminal. No Wireshark, no VM, no SIEM licence.**

---

## Play it

The case runs entirely in the browser — no build step, no installation, no account.
Progress is saved locally to the browser only.

Open `index.html` in any current browser and press **BEGIN INVESTIGATION**. It also
runs from a local disk over `file://`, and deploys unchanged as a static page (GitHub
Pages, Netlify, or any web server).

---

## The case

A session for `asmith` on `sec-win-05` — opened from an address outside the estate —
ran `Set-MpPreference -DisableRealtimeMonitoring $true` in PowerShell. Real-time
protection went off at 08:04:31, a folder exclusion was added 27 seconds later, and a
command shell was spawned 84 seconds after that.

Everything you are given — three alerts, the event stream, the account record, the
estate baseline — is in `new.scenario`. Nothing in this folder names a technique, an
indicator or a responsible host until you have earned it from the evidence. Note that
no malware is ever captured in this case: the host is disarmed before it is used, and
the missing payload is part of the finding.

---

## How the case works

| Stage | Name | What you do | XP |
|---|---|---|---|
| — | Briefing | Read the mission, press BEGIN | — |
| 01 | **Detect** | Open all five evidence items | 10 |
| 02 | **Collect** | Tag 25 log lines SIGNAL / CONTEXT / NOISE | 10 |
| 03 | **Correlate** | Order the timeline, name the pattern | 10 |
| 04 | **Connect** | Draw the threads on the pinboard | 10 |
| 05 | **Analyze** | Behaviour, change sequence, ATT&CK, classify IoCs | 42 |
| 06 | **Report** | Scope, findings, justification, confidence, response | 18 |

Then a debrief sheet: rank, XP ledger, preserved indicators, and your analyst journal.

**Analyst Assist** offers three levels of help and never blocks you. A wrong answer
lowers your score and rank; it never blocks progress, and any section can be
re-answered with **TRY AGAIN**. `RESET CASEFILE` clears saved progress.

---

## Files

| File | Purpose |
|---|---|
| `index.html` | the whole page: briefing, generic stage host, evidence modal, debrief sheet |
| `style.css` | the paper-and-stamp design system, print styles, reduced-motion support |
| `app.js` | the engine — six stages, scoring, XP ledger, save/resume, accessibility |
| `board.js` | the correlation board — draggable cards, drawn threads, keyboard support |
| `scenarios/beginner-defender-disabled-001.js` | the case: evidence, log stream, timeline, board, questions, IoCs, ranking |
| `new.scenario` | the JSON brief this case was built from — the source of truth for content |

The engine contains no facts about this case. Headings, ledger lines, the trail card
and the report preview all come from the scenario file's `engine` block, so a
different scenario is a different data file, not a different engine.

---

## Accessibility notes

- The whole game is playable with the keyboard alone. Tab to a board card and press
  Enter or Space to arm it, Tab to the second card and press Enter to choose a
  relation, then Enter on the verb. Escape cancels a pending thread.
- Focus is trapped inside the evidence modal and the debrief sheet, and returns to
  the element that opened them.
- `prefers-reduced-motion` is respected.
- There is a `@media print` block — the debrief sheet prints as a clean intelligence
  product.

## Browser support

Any current evergreen browser. Uses `localStorage`, Pointer Events, CSS custom
properties and `Element.closest`. Degrades to "plays without saving" if
`localStorage` is unavailable (private mode).