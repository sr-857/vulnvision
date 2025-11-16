"""HTTP security header reconnaissance for VulnVision."""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin

import requests

IMPORTANT_HEADERS: List[str] = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

USER_AGENT = "VulnVision-Headers/1.0"
DEFAULT_PROBES = ["/", "/index.html"]


def scan_domain(target_url: str) -> Dict[str, object]:
    """Fetch a representative page and evaluate headline security headers."""

    result: Dict[str, object] = {
        "headers": {},
        "present_headers": [],
        "missing_headers": [],
        "status_code": None,
    }

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    for path in DEFAULT_PROBES:
        probe_url = urljoin(target_url, path)
        try:
            response = session.get(probe_url, timeout=6, allow_redirects=True)
        except requests.RequestException:
            continue

        result["status_code"] = response.status_code
        headers = {k: v for k, v in response.headers.items()}
        result["headers"] = headers

        lowered = {k.lower(): v for k, v in headers.items()}
        present: List[str] = []
        missing: List[str] = []
        for header in IMPORTANT_HEADERS:
            if header in headers or header.lower() in lowered:
                present.append(header)
            else:
                missing.append(header)
        result["present_headers"] = present
        result["missing_headers"] = missing
        break  # stop after first successful probe

    return result
