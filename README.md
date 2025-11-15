# VulnVision

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

## License

Released under the MIT License. See [LICENSE](LICENSE).
