"""Technology detection utilities for VulnVision."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from mmh3 import hash as mmh3_hash

USER_AGENT = "VulnVision-TechDetect/1.0"

FAVICON_SIGNATURES: Dict[int, str] = {
    -247388890: "Apache Tomcat",
    -1372965829: "WordPress",
    -1520217781: "phpMyAdmin",
    116323821: "Django",
    968422740: "Nginx",
}

HEADER_SIGNATURES: Dict[str, Dict[str, str]] = {
    "server": {
        "cloudflare": "Cloudflare Edge",
        "nginx": "Nginx",
        "apache": "Apache HTTP Server",
        "iis": "Microsoft IIS",
    },
    "x-powered-by": {
        "php": "PHP",
        "express": "Express.js",
        "asp.net": "ASP.NET",
    },
    "set-cookie": {
        "wordpress": "WordPress",
        "laravel": "Laravel",
        "drupal": "Drupal",
    },
}

META_SIGNATURES: Dict[str, str] = {
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla!",
    "gatsby": "Gatsby",
    "next.js": "Next.js",
    "nuxt": "Nuxt.js",
}

SCRIPT_SIGNATURES: Dict[str, str] = {
    "wp-includes": "WordPress",
    "wp-content": "WordPress",
    "jquery": "jQuery",
    "react": "React",
    "angular": "AngularJS",
    "vue": "Vue.js",
}


@dataclass
class TechnologyFinding:
    name: str
    evidence: str
    confidence: str


def _add_finding(findings: List[TechnologyFinding], name: str, evidence: str, confidence: str) -> None:
    normalized = name.lower()
    if normalized in {f.name.lower() for f in findings}:
        return
    findings.append(TechnologyFinding(name=name, evidence=evidence, confidence=confidence))


def detect_from_headers(headers: Dict[str, str]) -> List[TechnologyFinding]:
    findings: List[TechnologyFinding] = []
    lowered = {k.lower(): v for k, v in headers.items() if isinstance(v, str)}
    for header, signatures in HEADER_SIGNATURES.items():
        value = lowered.get(header)
        if not value:
            continue
        value_lower = value.lower()
        for pattern, tech in signatures.items():
            if pattern in value_lower:
                _add_finding(findings, tech, f"{header}: {value}", "medium")
    return findings


def detect_from_meta(soup: BeautifulSoup) -> List[TechnologyFinding]:
    findings: List[TechnologyFinding] = []
    for meta in soup.find_all("meta"):
        for attr in ("name", "property"):
            key = meta.get(attr, "").lower()
            content = meta.get("content", "")
            if not content:
                continue
            for pattern, tech in META_SIGNATURES.items():
                if pattern in content.lower() or pattern in key:
                    _add_finding(findings, tech, f"meta {attr}={key}: {content}", "high")
    return findings


def detect_from_scripts(soup: BeautifulSoup) -> List[TechnologyFinding]:
    findings: List[TechnologyFinding] = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if not src:
            continue
        src_lower = src.lower()
        for pattern, tech in SCRIPT_SIGNATURES.items():
            if pattern in src_lower:
                _add_finding(findings, tech, f"script src={src}", "medium")
    return findings


def download_favicon(base_url: str, soup: BeautifulSoup) -> Optional[bytes]:
    rel_icon = soup.find("link", rel=re.compile("icon", re.IGNORECASE))
    href = rel_icon.get("href") if rel_icon else "/favicon.ico"
    favicon_url = urljoin(base_url, href)
    try:
        resp = requests.get(
            favicon_url,
            headers={"User-Agent": USER_AGENT},
            timeout=5,
            stream=True,
        )
        resp.raise_for_status()
        return resp.content[:1024 * 128]
    except requests.RequestException:
        return None


def detect_from_favicon(base_url: str, soup: BeautifulSoup) -> List[TechnologyFinding]:
    data = download_favicon(base_url, soup)
    if not data:
        return []
    try:
        encoded = base64.b64encode(data)
        favicon_hash = mmh3_hash(encoded)
    except Exception:
        return []
    tech = FAVICON_SIGNATURES.get(favicon_hash)
    if not tech:
        return []
    return [TechnologyFinding(name=tech, evidence=f"favicon hash {favicon_hash}", confidence="low")]


def detect_technologies(base_url: str, headers: Dict[str, str], html: str | None) -> List[Dict[str, str]]:
    findings: List[TechnologyFinding] = []
    findings.extend(detect_from_headers(headers))

    soup = BeautifulSoup(html, "html.parser") if html else None
    if soup is not None:
        findings.extend(detect_from_meta(soup))
        findings.extend(detect_from_scripts(soup))
        findings.extend(detect_from_favicon(base_url, soup))

    return [
        {
            "name": finding.name,
            "evidence": finding.evidence,
            "confidence": finding.confidence,
        }
        for finding in findings
    ]
