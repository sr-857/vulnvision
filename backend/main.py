from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, HttpUrl, validator

from .scanners.exposure import run_exposure_checks
from .scanners.headers import audit_security_headers
from .scanners.sslscan import analyze_certificate
from .scanners.techdetect import detect_technologies
from .utils.report import render_report

USER_AGENT = "VulnVision/1.0"

app = FastAPI(title="VulnVision", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: HttpUrl = Field(..., description="Target URL including scheme")

    @validator("target")
    def only_http_https(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme not in {"http", "https"}:
            raise ValueError("Only http and https schemes are supported")
        return value


class ScanResult(BaseModel):
    target: str
    fetched_url: str
    status_code: int | None
    response_headers: Dict[str, str]
    server_ip: str | None
    tech_stack: List[Dict[str, str]]
    security_headers: List[Dict[str, str | None]]
    ssl: Dict[str, Any]
    exposures: List[Dict[str, str]]
    risk: Dict[str, Any]
    scanned_at: str


def resolve_ip(hostname: str) -> str | None:
    try:
        ip = requests.get(f"https://dns.google/resolve?name={hostname}&type=A", timeout=5)
        ip.raise_for_status()
        answers = ip.json().get("Answer", [])
        for answer in answers:
            data = answer.get("data")
            if data:
                try:
                    ipaddress.ip_address(data)
                    return data
                except ValueError:
                    continue
    except requests.RequestException:
        return None
    return None


def fetch_target(url: str) -> tuple[requests.Response | None, str]:
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=10,
            allow_redirects=True,
        )
        response.raise_for_status()
        return response, response.url
    except requests.HTTPError as exc:
        if exc.response is not None:
            return exc.response, exc.response.url
        return None, url
    except requests.RequestException:
        return None, url


def compute_risk(
    headers_result: List[Dict[str, str | None]],
    ssl_result: Dict[str, Any],
    exposures: List[Dict[str, str]],
) -> Dict[str, Any]:
    level = "low"
    reasons: List[str] = []

    for header in headers_result:
        status = (header.get("status") or "").lower()
        if status == "missing":
            level = "high"
            reasons.append(f"Missing security header: {header['header']}")
        elif status == "needs_review" and level != "high":
            level = "medium"
            reasons.append(f"Header needs review: {header['header']}")

    for finding in ssl_result.get("findings", []):
        severity = (finding.get("severity") or "").lower()
        message = finding.get("message", "")
        if severity == "high":
            level = "high"
        elif severity == "medium" and level == "low":
            level = "medium"
        if message:
            reasons.append(f"SSL: {message}")

    for exposure in exposures:
        risk = (exposure.get("risk") or "").lower()
        detail = exposure.get("detail", exposure.get("path", ""))
        if risk == "high":
            level = "high"
        elif risk == "medium" and level == "low":
            level = "medium"
        if detail:
            reasons.append(f"Exposure: {detail}")

    if not reasons:
        reasons.append("No significant issues detected")

    return {"level": level.title(), "reasons": reasons}


def normalize_headers(headers: Any) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for key, value in headers.items():
        if isinstance(value, list):
            normalized[key] = ", ".join(str(v) for v in value)
        else:
            normalized[key] = str(value)
    return normalized


def perform_scan(target_url: str) -> ScanResult:
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid hostname in URL")

    response, final_url = fetch_target(target_url)
    response_headers: Dict[str, str] = {}
    status_code: int | None = None
    body: str | None = None

    if response is not None:
        response_headers = normalize_headers(response.headers)
        status_code = response.status_code
        body = response.text if response.headers.get("content-type", "").startswith("text") else None

    is_https = final_url.startswith("https")

    tech_stack = detect_technologies(final_url, response_headers, body)
    security_headers = audit_security_headers(response_headers, is_https=is_https)
    ssl_info = analyze_certificate(hostname) if is_https else {
        "present": False,
        "summary": None,
        "findings": [
            {"message": "Target not served over HTTPS", "severity": "medium"}
        ],
    }
    exposures = run_exposure_checks(final_url)
    risk = compute_risk(security_headers, ssl_info, exposures)

    server_ip = resolve_ip(hostname)

    return ScanResult(
        target=target_url,
        fetched_url=final_url,
        status_code=status_code,
        response_headers=response_headers,
        server_ip=server_ip,
        tech_stack=tech_stack,
        security_headers=security_headers,
        ssl=ssl_info,
        exposures=exposures,
        risk=risk,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/scan", response_model=ScanResult)
def scan(request: ScanRequest) -> ScanResult:
    return perform_scan(request.target)


@app.post("/report", response_class=HTMLResponse)
def report(request: ScanRequest) -> HTMLResponse:
    result = perform_scan(request.target)
    context = result.dict()
    html = render_report(context)
    return HTMLResponse(content=html, media_type="text/html")
