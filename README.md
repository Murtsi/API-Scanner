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

## Optional backend (MVP)

An optional backend scaffold now exists in `backend/` for queued server-side scans.

```bash
cd backend
npm install
npm run dev
```

Backend API: `http://localhost:8787`

Main endpoints:
- `GET /health`
- `POST /api/v1/scans`
- `GET /api/v1/scans`
- `GET /api/v1/scans/:id`
- `POST /api/v1/scans/:id/cancel`

From repo root you can also run:

```bash
npm run backend:dev
```

---

## Supabase + Vercel auth/admin setup

This project now includes:

- Supabase Auth login UI in the frontend
- Vercel serverless admin APIs under `api/admin/*`
- Admin panel for creating users and enabling/disabling access
- Per-user scan history saved to Supabase (`scan_runs`)

### 1) Frontend environment variables

Create `.env` from `.env.example` and set:

- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`
- `VITE_ADMIN_EMAILS` (comma-separated emails treated as admin in UI)

### 2) Vercel environment variables

In Vercel Project Settings → Environment Variables set:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `ADMIN_EMAILS` (same admin email allowlist)

### 3) Create your first admin user

In Supabase Dashboard → Authentication → Users, create a user with one of the `ADMIN_EMAILS` values.
Then sign in through the app login page. You will see the Admin Panel.

### 4) Admin APIs included

- `GET /api/admin/list-users`
- `POST /api/admin/create-user`
- `POST /api/admin/set-user-status`

All admin APIs require a valid bearer access token from a signed-in admin account.

### 5) Enable scan history table

Run [supabase/schema.sql](supabase/schema.sql) in Supabase SQL Editor.
This creates `public.scan_runs` with RLS policies so each user only sees/deletes their own saved scans.

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
