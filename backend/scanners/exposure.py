"""Passive exposure checks for VulnVision."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List
from urllib.parse import urljoin

import requests

USER_AGENT = "VulnVision-Exposure/1.0"
COMMON_PATHS: Dict[str, str] = {
    "/robots.txt": "robots.txt exposed",
    "/.git/config": "Git repository config exposed",
    "/.env": "Environment variables file exposed",
    "/.well-known/security.txt": "Security.txt present",
    "/admin": "Admin panel directory",
    "/login": "Login panel",
    "/backup.zip": "Potential backup archive",
    "/config.php": "Common PHP config file",
}

DIRECTORY_MARKERS = [
    "Index of /",
    "Directory listing for",
]

SENSITIVE_ROBOTS_PATTERNS = [
    re.compile(r"Disallow:\s*/(admin|backup|config|\.git)", re.IGNORECASE),
]


@dataclass
class ExposureFinding:
    path: str
    risk: str
    status: str
    detail: str


def fetch_url(url: str) -> requests.Response | None:
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=5,
            allow_redirects=True,
        )
        return resp
    except requests.RequestException:
        return None


def check_common_paths(base_url: str) -> List[ExposureFinding]:
    findings: List[ExposureFinding] = []
    for path, description in COMMON_PATHS.items():
        url = urljoin(base_url, path)
        resp = fetch_url(url)
        if resp is None:
            continue
        status = resp.status_code
        if status == 200:
            risk = "high" if path.startswith("/.git") or path.endswith(".env") else "medium"
            detail = description
            if any(marker in resp.text for marker in DIRECTORY_MARKERS):
                risk = "high"
                detail = "Directory listing enabled"
            findings.append(ExposureFinding(path=path, risk=risk, status=str(status), detail=detail))
        elif status in {401, 403}:
            findings.append(
                ExposureFinding(
                    path=path,
                    risk="low",
                    status=str(status),
                    detail="Path protected but accessible",
                )
            )
    return findings


def parse_robots(base_url: str) -> List[ExposureFinding]:
    url = urljoin(base_url, "/robots.txt")
    resp = fetch_url(url)
    if resp is None or resp.status_code != 200:
        return []
    findings: List[ExposureFinding] = []
    for pattern in SENSITIVE_ROBOTS_PATTERNS:
        if pattern.search(resp.text):
            findings.append(
                ExposureFinding(
                    path="/robots.txt",
                    risk="medium",
                    status="200",
                    detail="robots.txt reveals sensitive paths",
                )
            )
    return findings


def run_exposure_checks(base_url: str) -> List[Dict[str, str]]:
    findings = check_common_paths(base_url)
    findings.extend(parse_robots(base_url))
    return [f.__dict__ for f in findings]
