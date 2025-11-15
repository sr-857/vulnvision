# VulnVision — MVP

**One-liner:** Browser-first passive recon & misconfiguration analyzer.

**Demo:** Start backend (`uvicorn backend.main:app --reload`), open `frontend/index.html`, enter a domain, click **Scan**, then export the HTML report — under 60 seconds.

**Ethics:** This tool performs non-intrusive, passive checks only. Scan targets only with explicit permission.

---

Web-based passive reconnaissance and misconfiguration analysis platform.

## Overview

VulnVision delivers non-intrusive triage for security analysts by collecting passive intelligence about a target domain. The MVP focuses on:

- Technology detection
- Security header auditing
- SSL/TLS certificate review
- Exposure checks for common misconfigurations
- Analyst-friendly risk classification
- Color-coded dashboard for quick scanning
- Exportable HTML report for sharing results

## Stack

- **Backend:** FastAPI, requests, dnspython
- **Frontend:** HTML, TailwindCSS, Alpine.js
- **Reporting:** Jinja2 templates rendered server-side
- **Runtime:** Uvicorn

## Project Layout

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
 ├── README.md
 ├── LICENSE
 └── .gitignore
```

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
2. Run the API server:
   ```bash
   uvicorn backend.main:app --reload
   ```
3. Open `frontend/index.html` in your browser to access the dashboard.

## Demo Assets

- Export an HTML report from a safe target (e.g., OWASP Juice Shop) and save it as `examples/demo_report.html` for judges to preview without running a scan.
- Capture screenshots of the dashboard (`screenshots/dashboard.png`) and generated report (`screenshots/report.png`) to showcase the UI in submission materials.
- See additional guidance in `examples/README.md`.

## License

Released under the MIT License. See [LICENSE](LICENSE).
