# UI Reconnect Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire all existing UI components into App.jsx using a two-column layout, and fix LoginPanel.jsx to use the app.css design system instead of Tailwind.

**Architecture:** App.jsx is the single orchestrator — it holds all shared state (session, scan options, url input) and passes props down to each component. The layout is a sticky two-column main grid (ScannerPanel left, ResultsPanel right) with collapsible bottom panels for Rules, History, and Admin.

**Tech Stack:** React 18, Vite 5, custom CSS design system in `src/styles/app.css`. No Tailwind. No new dependencies.

---

## Task 1: Add layout CSS classes to app.css

**Files:**
- Modify: `src/styles/app.css` (append to end of file)

**Step 1: Append the following CSS to the end of `src/styles/app.css`**

```css
/* ═══════════════════════════════════════════════════════════════
   App layout — two-column grid + auth page
═══════════════════════════════════════════════════════════════ */

/* ── Auth / login page ──────────────────────────────────────── */

.auth-page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 32px;
  padding: 32px 16px;
  background: var(--bg);
}

.auth-brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
}

.auth-logo {
  width: 52px;
  height: 52px;
  color: var(--accent);
}

.auth-logo svg {
  width: 100%;
  height: 100%;
}

.auth-title {
  font-family: 'Inter', sans-serif;
  font-size: 2rem;
  font-weight: 800;
  color: var(--text);
  letter-spacing: -1px;
  margin: 0;
}

.auth-title span {
  color: var(--accent);
}

.auth-subtitle {
  font-size: 0.85rem;
  color: var(--text-muted);
  margin: 0;
  letter-spacing: 0.02em;
}

/* ── Main two-column grid ───────────────────────────────────── */

#app {
  min-height: 100vh;
  background: var(--bg);
  display: flex;
  flex-direction: column;
}

.main-grid {
  display: grid;
  grid-template-columns: 5fr 8fr;
  gap: 24px;
  padding: 24px;
  align-items: start;
  flex: 1;
}

.col-scanner {
  position: sticky;
  top: 24px;
  max-height: calc(100vh - 72px - 48px);
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}

.col-results {
  min-width: 0;
}

/* ── Bottom panels row ──────────────────────────────────────── */

.bottom-panels {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 24px;
  padding: 0 24px 32px;
}

/* ── Responsive ─────────────────────────────────────────────── */

@media (max-width: 900px) {
  .main-grid {
    grid-template-columns: 1fr;
  }

  .col-scanner {
    position: static;
    max-height: none;
    overflow-y: visible;
  }

  .bottom-panels {
    grid-template-columns: 1fr;
  }
}
```

**Step 2: Verify the file saved correctly**

Open `src/styles/app.css`, scroll to the bottom — the new CSS block should be present.

**Step 3: Commit**

```bash
git add src/styles/app.css
git commit -m "style: add two-column layout and auth page CSS"
```

---

## Task 2: Fix LoginPanel.jsx — replace Tailwind with design system CSS

**Files:**
- Modify: `src/components/LoginPanel.jsx`

**Context:** The shield SVG is already in `Header.jsx` — copy just the `<svg>` element into the auth brand area of the login page. `signInWithEmail` is imported from `src/lib/auth.js` and already wired from the previous security fix session.

**Step 1: Replace the full contents of `src/components/LoginPanel.jsx`**

```jsx
import React, { useState } from 'react'
import { signInWithEmail } from '../lib/auth.js'

const ShieldIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path
      d="M12 2L4 6V12C4 16.42 7.61 20.57 12 22C16.39 20.57 20 16.42 20 12V6L12 2Z"
      fill="rgba(232,64,74,0.15)"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M9 12L11 14L15 10"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
)

export default function LoginPanel({ onLogin }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const user = await signInWithEmail(email, password)
      onLogin(user)
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-brand">
        <div className="auth-logo">
          <ShieldIcon />
        </div>
        <h1 className="auth-title">API<span>Scanner</span></h1>
        <p className="auth-subtitle">Professional Security Assessment Platform</p>
      </div>

      <div className="auth-card">
        {error && <div className="auth-error">{error}</div>}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <input
            className="auth-input"
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
          />
          <input
            className="auth-input"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
          <button
            type="submit"
            className="btn-primary"
            disabled={loading}
            style={{ marginTop: '4px' }}
          >
            {loading ? 'Logging in…' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  )
}
```

**Note:** `LoginPanel` now renders its own full page (auth-page + auth-brand + auth-card). `App.jsx` will render `<LoginPanel onLogin={handleLogin} />` directly without wrapping it in any extra div.

**Step 2: Commit**

```bash
git add src/components/LoginPanel.jsx
git commit -m "fix: replace Tailwind login with design system CSS"
```

---

## Task 3: Rewrite App.jsx — wire all components

**Files:**
- Modify: `src/App.jsx`

**Props reference before writing:**
- `useScanner()` → `{ results, log, isScanning, startScan, stopScan, clearAll, hydrateFromHistory }`
- `ScannerPanel` props → `{ urlsInput, setUrlsInput, customRulesInput, setCustomRulesInput, passiveModules, options, setOptions, isScanning, log, onScan, onStop, onClear }`
- `ResultsPanel` props → `{ results, isScanning, onExportJson, onExportCsv }`
- `HistoryPanel` props → `{ refreshToken, onLoadRun }`
- `Header` props → `{ user, isAdmin, onSignOut }`
- `AdminPanel` → no props
- `RulesPanel` → no props
- `PASSIVE_MODULES` → imported from `../utils/passiveModules.js`
- `passiveModuleDefaults()` → initial value for `options` state
- `exportJson(results)` / `exportCsv(results)` → imported from `../utils/export.js`
- `getSession()` returns `{ user: { email, role } }` or `null`
- `isAdminUser(user)` checks `VITE_ADMIN_EMAILS` env var against `user.email`

**Step 1: Replace the full contents of `src/App.jsx`**

```jsx
import React, { useState, useCallback } from 'react'
import Header from './components/Header'
import LoginPanel from './components/LoginPanel'
import ScannerPanel from './components/ScannerPanel'
import ResultsPanel from './components/ResultsPanel'
import HistoryPanel from './components/HistoryPanel'
import RulesPanel from './components/RulesPanel'
import AdminPanel from './components/AdminPanel'
import { useScanner } from './hooks/useScanner'
import { getSession, signOut, isAdminUser } from './lib/auth'
import { PASSIVE_MODULES, passiveModuleDefaults } from './utils/passiveModules'
import { exportJson, exportCsv } from './utils/export'
// NO CSS import — app.css is loaded in main.jsx

function App() {
  const [session, setSession] = useState(() => getSession())
  const [urlsInput, setUrlsInput] = useState('')
  const [customRulesInput, setCustomRulesInput] = useState('')
  const [options, setOptions] = useState(passiveModuleDefaults)
  const [historyRefreshToken, setHistoryRefreshToken] = useState(0)

  const { results, log, isScanning, startScan, stopScan, clearAll, hydrateFromHistory } =
    useScanner()

  // getSession() returns { user: {...} } — extract the user object
  const user = session?.user ?? session
  const isAdmin = isAdminUser(user)

  const handleLogin = (user) => setSession({ user })

  const handleSignOut = () => {
    signOut()
    setSession(null)
  }

  const handleScan = useCallback(async () => {
    await startScan(urlsInput, customRulesInput, options)
    setHistoryRefreshToken((t) => t + 1)
  }, [startScan, urlsInput, customRulesInput, options])

  const handleClear = useCallback(() => {
    clearAll()
    setUrlsInput('')
  }, [clearAll])

  const handleLoadRun = useCallback((run) => {
    hydrateFromHistory(run.result)
  }, [hydrateFromHistory])

  if (!session) {
    return <LoginPanel onLogin={handleLogin} />
  }

  return (
    <div id="app">
      <Header user={user} isAdmin={isAdmin} onSignOut={handleSignOut} />

      <main className="main-grid">
        <div className="col-scanner">
          <ScannerPanel
            urlsInput={urlsInput}
            setUrlsInput={setUrlsInput}
            customRulesInput={customRulesInput}
            setCustomRulesInput={setCustomRulesInput}
            passiveModules={PASSIVE_MODULES}
            options={options}
            setOptions={setOptions}
            isScanning={isScanning}
            log={log}
            onScan={handleScan}
            onStop={stopScan}
            onClear={handleClear}
          />
        </div>

        <div className="col-results">
          <ResultsPanel
            results={results}
            isScanning={isScanning}
            onExportJson={() => exportJson(results)}
            onExportCsv={() => exportCsv(results)}
          />
        </div>
      </main>

      <div className="bottom-panels">
        <RulesPanel />
        <HistoryPanel
          refreshToken={historyRefreshToken}
          onLoadRun={handleLoadRun}
        />
        {isAdmin && <AdminPanel />}
      </div>
    </div>
  )
}

export default App
```

**Step 2: Verify the build compiles without errors**

```bash
cd c:/Users/Murts/Documents/GitHub/API-Scanner
npm run build
```

Expected: build completes with no errors. Warnings about bundle size are acceptable.

**Step 3: Start dev server and verify visually**

```bash
npm run dev
```

Open `http://localhost:5173`. Expected:
- Login page: dark background, shield logo, "APIScanner Pro" title, email + password inputs, red Login button
- After login: Header bar with shield logo + detection stats + user pill, two-column grid with ScannerPanel left and ResultsPanel right, bottom row with Rules / History / Admin panels
- On a browser window < 900px wide: panels stack to single column

**Step 4: Commit**

```bash
git add src/App.jsx
git commit -m "feat: wire all components into two-column layout"
```

---

## Task 4: Smoke test the full scan flow

**Step 1: Test login**

Navigate to `http://localhost:5173`. Enter any email + a password. Confirm:
- If backend is not running: error message appears inline in the login card (not a blank page crash)
- If backend is running with correct credentials: redirect to main app

**Step 2: Test scan**

In the ScannerPanel, enter `https://example.com` in the textarea. Click "Start scan". Confirm:
- Scan log appears below the Start/Clear buttons in the left column
- Results appear in the right column as findings come in
- After scan completes, the history refresh fires (HistoryPanel reloads — may show error if DB not connected, which is expected)

**Step 3: Test stop/clear**

During a scan click "Stop scan". Confirm scanning stops. Click "Clear" — both log and results clear, URL input resets to empty.

**Step 4: Test export**

After a scan with results, click "Export JSON" and "Export CSV" in ResultsPanel. Confirm file downloads trigger.

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: verify two-column layout smoke tests pass"
```

---

## Summary of changes

| File | Action |
|---|---|
| `src/styles/app.css` | Append layout CSS (auth page + two-column grid + bottom panels + responsive) |
| `src/components/LoginPanel.jsx` | Remove Tailwind, use design system, include brand/logo above card |
| `src/App.jsx` | Full rewrite — wire all 6 components, two-column layout, correct state/prop wiring |
