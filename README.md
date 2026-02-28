# API Scanner

A client-side web security scanner for finding exposed secrets, testing endpoints for injection vulnerabilities, and auditing HTTP security headers — all without sending data to a third-party server.

![React](https://img.shields.io/badge/React-18-61dafb?logo=react&logoColor=white&labelColor=0d1117)
![Vite](https://img.shields.io/badge/Vite-5-646cff?logo=vite&logoColor=white&labelColor=0d1117)
![License](https://img.shields.io/badge/License-MIT-e8404a?labelColor=0d1117)

---

## What it does

**Passive scanning**
- Detects 49+ secret patterns — AWS keys, Stripe tokens, GitHub PATs, database DSNs, private keys, JWTs, and more
- Crawls linked JavaScript bundles for exposed credentials
- Checks 30+ common paths for exposed files (`.env`, `.git/config`, `swagger.json`, backups, etc.)
- Analyses HTTP response headers for missing security controls (HSTS, CSP, X-Frame-Options, CORS)
- High-entropy string detection for secrets that don't match a named pattern

**Active testing** (opt-in, requires permission)
- SQL injection — error-based (20 payloads, 45 DB/ORM error signatures)
- SQL injection — time-based blind (SLEEP/WAITFOR/pg_sleep across 4 databases)
- NoSQL injection — MongoDB operator injection via URL parameters
- XSS reflection — reflected input detection across discovered endpoints

Each finding includes a plain-English explanation, real attack scenario, and step-by-step fix — useful if you're sharing results with a non-technical team.

---

## Getting started

```bash
npm install
npm run dev
```

Open `http://localhost:5173`

**Build for production**

```bash
npm run build   # output → dist/
```

---

## Usage

1. Paste one or more URLs (one per line).
2. Toggle passive checks — JS assets, exposed files, security headers.
3. Optionally enable active tests. These send real payloads; only use on systems you own or have written permission to test.
4. Click **Start scan**.
5. Expand any finding → click **Learn more** for a beginner-friendly breakdown.
6. Export results as JSON or CSV.

**Custom rules**

Add your own regex patterns in Advanced settings:

```
RuleName::/pattern/flags
```

---

## Project structure

```
src/
  components/       ScannerPanel, ResultsPanel, RulesPanel, Header
  hooks/            useScanner.js — scan orchestration
  utils/
    scanner.js          fetch, pattern matching, asset crawling
    patterns.js         49 built-in detection rules
    entropy.js          Shannon entropy detection
    headerAnalyzer.js   HTTP security header checks
    endpointExtractor.js  API endpoint discovery from HTML/JS
    vulnScanner.js      SQLi, time-based blind, NoSQL, XSS testing
    export.js           JSON/CSV export
  config/           constants, exposed path list
  styles/           app.css
```

---

## Tech stack

React 18 · Vite 5 · plain CSS (no UI library) · browser Fetch API — no backend, no tracking, everything runs locally.

---

## Ethics

Only scan targets you own or have explicit written permission to test. Active tests send real payloads to servers.
