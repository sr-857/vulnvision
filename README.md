# VulnVision 🚀

**One-liner:** Browser-first passive recon & misconfiguration analyzer.

**Demo:** Start backend (`uvicorn backend.main:app --reload`), open `frontend/index.html`, enter a domain, click **Scan**, then export the HTML report — under 60 seconds.

> **Ethics:** VulnVision performs non-intrusive, passive checks only. Scan targets exclusively with explicit permission.

---

Web-based passive recon & security posture analyzer. Tech detection, SSL checks, exposure analysis, security-header grading, color-coded dashboard, HTML reports.

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
   uvicorn backend.main:app --reload
   ```
3. Open `frontend/index.html` in your browser, enter a target URL, and click **Scan**.

## 🛠️ Specialist Demo (Docker)

```bash
./scripts/demo.sh
```

- Backend: http://localhost:8000
- Frontend: http://localhost:8080
- Stop stack: `docker compose down` (or `docker-compose down`)

For hosted demos, set `API_BASE` when building the frontend container or edit `frontend/config.js` to hardcode your backend URL.

## 🎬 Demo Assets

- Export a sample HTML report (e.g., OWASP Juice Shop) to `examples/demo_report.html` for offline judging.
- Capture dashboard and report screenshots (`screenshots/dashboard.png`, `screenshots/report.png`).
- See `examples/README.md` for guidance on organizing media.

## 📦 Release Checklist

- Tag the MVP release: `git tag -a v0.1 -m "vulnvision: MVP release" && git push origin v0.1`
- Publish release notes with feature summary and demo links.

## 📄 License

Released under the MIT License. See [LICENSE](LICENSE).
