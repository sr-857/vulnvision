"""Passive exposure probes for VulnVision."""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin

import requests

COMMON_CHECKS: List[str] = [
    "/.git/",
    "/.env",
    "/backup.zip",
    "/config.php",
    "/admin",
    "/phpinfo.php",
    "/robots.txt",
]

USER_AGENT = "VulnVision-Exposure/1.0"


def scan_domain(target_url: str) -> Dict[str, object]:
    result: Dict[str, object] = {"host": target_url, "exposures": []}

    for path in COMMON_CHECKS:
        url = urljoin(target_url, path)
        try:
            response = requests.get(url, timeout=4, allow_redirects=False, headers={"User-Agent": USER_AGENT})
        except requests.RequestException:
            continue

        entry: Dict[str, object] = {
            "path": path,
            "status": response.status_code,
            "detail": "",
        }

        if response.status_code == 200:
            if path == "/robots.txt":
                entry["detail"] = "robots.txt reveals sensitive paths"
            result["exposures"].append(entry)
        elif response.status_code in (301, 302) and path == "/admin":
            entry["detail"] = "Admin portal redirect"
            result["exposures"].append(entry)

    return result
