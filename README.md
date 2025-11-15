# VulnVision 🚀

**One-liner:** Browser-first passive recon & misconfiguration analyzer.

**Demo:** Start backend (`uvicorn backend.main:app --reload`), open `frontend/index.html`, enter a domain, click **Scan**, then export the HTML report — under 60 seconds.

> **Ethics:** VulnVision performs non-intrusive, passive checks only. Scan targets exclusively with explicit permission.

---

Web-based passive recon & security posture analyzer. Tech detection, SSL checks, exposure analysis, security-header grading, color-coded dashboard, HTML reports.

## Status overview

- 📦 Latest release: [GitHub Releases](https://github.com/sr-857/vulnvision/releases)
- 📄 License: [MIT](./LICENSE)
- 🌐 Live demo: [https://sr-857.github.io/vulnvision](https://sr-857.github.io/vulnvision)
- 🔍 CodeQL scan: _coming soon_
- 🐳 Docker image: _planned_

## 🔍 Overview

VulnVision delivers analyst-friendly reconnaissance by gathering passive intelligence about a target. The MVP highlights:

- 🧠 Technology fingerprints
- 🛡️ Security-header grading
- 🔐 SSL/TLS certificate inspection
- 🚪 Exposure spotting for common misconfigurations
- 📊 Risk classification with clear rationale
- 🎨 Color-coded dashboard and exportable HTML report

## 🧰 Tech Stack

- **Backend:** FastAPI, requests, dnspython
- **Frontend:** HTML, TailwindCSS, Alpine.js
- **Reporting:** Jinja2 templates rendered server-side
- **Runtime:** Uvicorn

## 🗂️ Project Layout

```
vulnvision/
 ├── backend/
 │   ├── main.py
 │   ├── scanners/
 │   │   ├── headers.py
 │   │   ├── sslscan.py
 │   │   ├── techdetect.py
 │   │   └── exposure.py
 │   └── utils/report.py
 ├── frontend/
 │   ├── index.html
 │   ├── dashboard.js
 │   └── styles.css
 ├── examples/
 │   └── README.md
 ├── .github/workflows/
 │   └── ci.yml
 ├── README.md
 ├── LICENSE
 └── .gitignore
```

## ⚡ Quick Start

1. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
2. Run the API server:
   ```bash
   uvicorn backend.main:app --reload --port 8000
   ```
3. Open `frontend/index.html` in your browser, enter a target URL, and click **Scan**.

## 🛠️ Specialist Demo (Docker Compose)

```bash
./scripts/demo.sh
# Frontend → http://localhost:8080
# Backend  → http://localhost:8000

# Stop stack
docker compose down
```

To target a hosted API, rebuild the frontend container with `API_BASE=https://your-api-host` or set `window.VULNVISION_API_BASE` in `frontend/config.js`.

## 🚀 Deployment Playbook

| Scenario | Action |
| --- | --- |
| Local manual | `uvicorn backend.main:app --reload --port 8000` + open `frontend/index.html` |
| Docker backend only | `docker build -t vulnvision-backend ./backend` → `docker run -p 8000:8000 vulnvision-backend` |
| Full Docker stack | `docker compose up --build` |
| Render/Fly.io | Deploy backend container; configure frontend `API_BASE` |
| GitHub Pages | Serve `frontend/` statically with `window.VULNVISION_API_BASE` pointing to hosted backend |

## 🎯 Recruiter Walkthrough (3 minutes)
1. **Context (30s)** — “VulnVision mirrors the passive recon phase: fingerprint stack, surface misconfigurations, tell the risk story.”
2. **Live scan (60s)** — Launch the Docker demo or local server, scan `https://demo.owasp-juice.shop`.
3. **Insights (60s)** — Walk through risk badge, missing headers, TLS findings, exposure hits, and tech fingerprints.
4. **Deliverable (30s)** — Export the HTML report to demonstrate analyst handoff quality.
5. **Close (30s)** — Emphasise passive-only posture, quick triage value, and extendable scanners.

## 🎬 Demo Assets
- Save a sample exported report to `examples/demo_report.html` for offline judging.
- Capture dashboard/report screenshots in `screenshots/` for README and releases.
- Visit the static walkthrough: [https://sr-857.github.io/vulnvision](https://sr-857.github.io/vulnvision)

## 🧪 Quality & CI
- CI installs dependencies, runs `compileall` lint, and executes pytest smoke tests.
- Roadmap includes CodeQL security analysis and expanded test coverage.

## 🗓️ Roadmap
- [ ] Add unit tests for scanner modules
- [ ] Publish GitHub Pages walkthrough with real scan artefacts
- [ ] Integrate CodeQL static analysis workflow
- [ ] Extend exposure checks (cloud storage, sitemap leaks)
- [ ] Enrich reports with DNS/WHOIS context

## 📦 Release Playbook
- Tag releases: `git tag -a vX.Y.Z -m "VulnVision vX.Y.Z"` → `git push origin vX.Y.Z`
- Draft notes via [`docs/releases/RELEASE_NOTES_TEMPLATE.md`](docs/releases/RELEASE_NOTES_TEMPLATE.md)
- Publish using `gh release create ...` with screenshots and sample HTML report attached.

## 📄 License

Released under the MIT License. See [LICENSE](LICENSE).
