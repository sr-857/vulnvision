# VulnVision Architecture

VulnVision delivers a passive web reconnaissance workflow that analysts can run from any browser. The platform is intentionally split into lightweight, composable layers so it can be deployed on a laptop for demos or hosted in the cloud without additional services.

## Layered View

```
┌───────────────────────────────┐
│     Analyst Browser Client    │
│  ───────────────────────────  │
│  • Tailwind + Alpine.js UI    │
│  • Fetch → Scan → Report flow │
│  • Exportable HTML reports    │
└────────────▲──────────────────┘
             │ REST
┌────────────┴──────────────────┐
│          FastAPI API          │
│  ───────────────────────────  │
│  • `/scan` orchestrator       │
│  • `/report` Jinja rendering  │
│  • Validation & CORS          │
└────────────▲──────────────────┘
             │ Delegation
┌────────────┴──────────────────┐
│         Scanner Suite          │
│  ───────────────────────────   │
│  • headers.py (security audit) │
│  • sslscan.py (TLS insights)   │
│  • techdetect.py (stack hints) │
│  • exposure.py (passive risks) │
└────────────▲──────────────────┘
             │ Utilities
┌────────────┴──────────────────┐
│     Report & Config utils     │
│  ───────────────────────────  │
│  • Jinja2 HTML template        │
│  • Risk scoring heuristics    │
└────────────┴──────────────────┘
```

## Backend (FastAPI)
- **Scan orchestration** coordinates HTTP fetch, scanner execution, and risk scoring.
- **Risk engine** converts scanner findings into Low/Medium/High posture with supporting rationale.
- **Report endpoint** renders an analyst-friendly HTML export using Jinja2 templates.
- **Extensibility**: new scanners can be dropped into `backend/scanners/` and wired into `perform_scan`.

### Key Modules
| Module | Responsibility |
| --- | --- |
| `backend/main.py` | FastAPI app, request models, scan orchestration, risk computation |
| `backend/scanners/headers.py` | Grades critical response headers for presence and quality |
| `backend/scanners/sslscan.py` | Inspects live TLS certificates (expiry, key size, SAN match) |
| `backend/scanners/techdetect.py` | Uses headers, HTML, and favicon hashing to infer technology stack |
| `backend/scanners/exposure.py` | Checks for passive exposures (robots.txt hints, .git, .env, admin panels) |
| `backend/utils/report.py` | Renders HTML reports via Jinja2 |

## Frontend (Tailwind + Alpine.js)
- Single-page dashboard with collapsible sections for risk, technology stack, headers, SSL, exposures, and raw headers.
- Uses `fetch` to call the API and populate UI without a build step.
- Export button posts to `/report` and triggers download of analyst-ready HTML.
- Supports runtime API host overrides via `window.VULNVISION_API_BASE` for hosted deployments.

## Reporting Layer
- `backend/templates/report.html` mirrors the UI, ensuring exported reports reflect the live scan.
- Color-coded badges match on-screen severity for consistency.

## Deployment Modes
| Scenario | Approach |
| --- | --- |
| Local developer setup | `uvicorn backend.main:app --reload` + open `frontend/index.html` |
| Specialist demo | `docker-compose up --build` via `scripts/demo.sh` to run backend + Nginx frontend |
| Hosted backend | Deploy FastAPI container (Render/Fly/etc.) and point frontend `API_BASE` to hosted URL |
| GitHub Pages preview | Serve `frontend/` statically; set `window.VULNVISION_API_BASE` to remote API |

## Data Flow Summary
1. **Request**: Analyst submits target URL from dashboard.
2. **Fetch**: FastAPI issues a single GET, respecting redirects and capturing headers/body.
3. **Scanners**: Each scanner analyzes its domain (headers, TLS, exposures, tech stack).
4. **Risk**: Findings are normalized into rationale statements and severity levels.
5. **Return**: Combined response is sent back to the frontend for visualization and reporting.
6. **Export**: Optional HTML report is rendered server-side for sharing with stakeholders.

## Security Considerations
- Strictly passive: no brute forcing, no aggressive fuzzing, single request per endpoint.
- Timeout and error handling prevent long-running scans from hanging the UI.
- TLS inspection is read-only (no MITM) and degrades gracefully if HTTPS is unavailable.
- CORS allows cross-origin requests for the static frontend; tighten as needed for hosted deployments.

## Extending VulnVision
- **New checks**: add a module under `backend/scanners/` and hook into `perform_scan`.
- **Custom report styling**: update `backend/templates/report.html` and `frontend/styles.css`.
- **Automation**: wrap `/scan` into scheduled tasks or integrate into CI for posture monitoring.

Refer to `README.md` for quickstart commands, demo scripts, and deployment guidance.
