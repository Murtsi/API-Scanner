# API-Scanner

> Secret & API Key Detector for public websites

![Status](https://img.shields.io/badge/status-active-red)
![Tech](https://img.shields.io/badge/react-vite-black)
![License](https://img.shields.io/badge/license-MIT-red)

A fast, client‑side scanner that searches public pages for exposed keys, tokens, and hardcoded secrets. The UI uses a dark, red‑accented theme designed for quick triage.

---

## ✨ Features

- **Multi‑rule detection** for common API keys, tokens, and credential patterns
- **High‑entropy detection** for suspicious random strings
- **Asset crawling** for linked JS bundles (optional)
- **Exposed file checks** (e.g., .env, swagger.json, backups)
- **Custom regex rules**
- **Export** results to JSON or CSV
- **Human‑friendly risk notes** explaining why exposure matters

---

## 🧭 Quick Start

```bash
npm install
npm run dev
```

Open http://localhost:5173/

---

## 🧪 How to Use

1. Paste one URL per line.
2. Toggle optional checks (JS assets, exposed files).
3. Add custom regex rules if needed.
4. Start scan and review findings.
5. Export to JSON/CSV if required.

### Custom Rule Format

```
MyRule::/sk_live_[A-Za-z0-9]{24,}/g
```

---

## 📌 What It Scans

- **HTML content** of each target URL
- **Linked JS assets** (optional)
- **Common exposed files** on the same origin (optional)

---

## 🛡️ Safety & Ethics

Only scan systems you own or have explicit permission to test. This tool is for defensive security and auditing.

---

## 🚀 Build

```bash
npm run build
```

Output: `dist/`

> If deploying on Vercel and you see a permission error, this project uses a Node‑based build command in package.json to avoid that issue.

---

## 📁 Project Structure

```
src/
  components/
  styles/
  App.jsx
  main.jsx
```

---

## 🧩 Roadmap Ideas

- Server‑side proxy for deeper scans (bypassing CORS where permitted)
- Recursive crawling and sitemap support
- Rule packs for specific platforms
