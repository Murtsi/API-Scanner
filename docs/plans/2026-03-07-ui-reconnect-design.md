# UI Reconnect Design — API Scanner Pro
Date: 2026-03-07

## Problem
`App.jsx` was stripped to a barebones skeleton that only renders 3 hardcoded stat cards.
Six fully-built, polished components exist but are disconnected. `LoginPanel.jsx` uses
Tailwind classes that are not installed, rendering as completely unstyled HTML.

## Goal
Reconnect all existing components through `App.jsx` using Approach A (two-column layout).
Fix `LoginPanel.jsx` to use the `app.css` design system. No new visual design — restore the
already-built UI.

## Layout: Approach A — Two-Column

### Login Page
- Full-screen dark background (`--bg: #060a12`)
- Centered glass card (`auth-card` class)
- Shield SVG logo + "APIScanner Pro" brand above form
- Email + password inputs (`auth-input`)
- Login button (`btn-primary`, `--accent` red)
- Inline error display

### Post-login structure
```
Header (full width)
  logo | detection-stats | user-pill + sign-out

Main grid (grid-template-columns: 5fr 8fr, gap 24px, single-col below 900px)
  LEFT  — ScannerPanel (sticky top:0, scanner config + log)
  RIGHT — ResultsPanel (findings, filters, export)

Bottom row (3 collapsible cards)
  RulesPanel | HistoryPanel | AdminPanel (admin only)
```

## Component Wiring

### App.jsx responsibilities
- Session init: `getSession()` on first render (lazy useState initializer)
- `isAdmin`: derived from `isAdminUser(session?.user ?? session)`
- `useScanner` hook → props spread to `ScannerPanel` + `ResultsPanel`
- `historyRefreshToken`: bumped after each scan completes to trigger HistoryPanel reload
- Export handlers: `onExportJson` / `onExportCsv` from `src/utils/export.js`
- `handleSignOut`: calls `signOut()` + `setSession(null)`

### LoginPanel.jsx responsibilities
- Remove all Tailwind classes
- Use `auth-card`, `auth-input`, `btn-primary`, `auth-error` CSS classes
- Keep real auth: `signInWithEmail(email, password)` from `src/lib/auth.js`
- Show inline error on failure

## Files to Change
| File | Change |
|---|---|
| `src/App.jsx` | Full rewrite — wire all components, two-column layout |
| `src/components/LoginPanel.jsx` | Remove Tailwind, use design system CSS classes |

## Files Unchanged
All other components are already built and correct:
- `src/components/Header.jsx`
- `src/components/ScannerPanel.jsx`
- `src/components/ResultsPanel.jsx`
- `src/components/HistoryPanel.jsx`
- `src/components/RulesPanel.jsx`
- `src/components/AdminPanel.jsx`
- `src/styles/app.css`
- `src/hooks/useScanner.js`
- `src/utils/export.js`
