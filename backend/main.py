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


def flatten_headers(headers: Any) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for key, value in headers.items():
        if isinstance(value, list):
            normalized[key] = ", ".join(str(v) for v in value)
        else:
            normalized[key] = str(value)
    return normalized


def normalize_tech_stack(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    normalized: List[Dict[str, str]] = []
    for entry in findings:
        normalized.append(
            {
                "name": entry.get("name", "Unknown"),
                "confidence": entry.get("confidence", "Unknown"),
                "evidence": entry.get("evidence", ""),
            }
        )
    return normalized


def format_security_headers(headers_result: List[Dict[str, str | None]]) -> List[Dict[str, str]]:
    formatted: List[Dict[str, str]] = []
    for header in headers_result:
        status = (header.get("status") or "").lower()
        formatted.append(
            {
                "header": header.get("header", ""),
                "status": status,
                "value": header.get("value") or "",
                "note": header.get("note") or "",
            }
        )
    return formatted


def normalize_tls(ssl_result: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any]]:
    present = ssl_result.get("present")
    summary = ssl_result.get("summary") or {}
    findings = ssl_result.get("findings") or []
    normalized_summary: Dict[str, Any] | None = None
    if present and summary:
        normalized_summary = {
            "subject": summary.get("subject", ""),
            "issuer": summary.get("issuer", ""),
            "not_before": summary.get("not_before"),
            "not_after": summary.get("not_after"),
            "days_remaining": summary.get("days_remaining"),
            "signature_algorithm": summary.get("signature_algorithm"),
            "key_type": summary.get("key_type"),
            "key_size": summary.get("key_size"),
            "san": summary.get("san", []),
        }

    normalized_findings = [
        {
            "message": finding.get("message", ""),
            "severity": (finding.get("severity") or "unknown").lower(),
        }
        for finding in findings
    ]

    # Legacy findings may appear in the root tls dict; include them.
    root_findings = ssl_result.get("findings") or []
    if isinstance(root_findings, list):
        normalized_findings.extend(
            {
                "message": item.get("message", ""),
                "severity": (item.get("severity") or "unknown").lower(),
            }
            for item in root_findings
        )

    # Deduplicate findings
    seen: set[tuple[str, str]] = set()
    unique_findings: List[Dict[str, str]] = []
    for item in normalized_findings:
        key = (item["message"], item["severity"])
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(item)

    tls_payload = {
        "present": bool(present and normalized_summary),
        "subject": (normalized_summary or {}).get("subject", ""),
        "issuer": (normalized_summary or {}).get("issuer", ""),
        "valid_from": (normalized_summary or {}).get("not_before"),
        "valid_to": (normalized_summary or {}).get("not_after"),
        "days_remaining": (normalized_summary or {}).get("days_remaining"),
        "key_type": (normalized_summary or {}).get("key_type"),
        "key_size": (normalized_summary or {}).get("key_size"),
        "signature": (normalized_summary or {}).get("signature_algorithm"),
        "san": (normalized_summary or {}).get("san", []),
        "findings": [item["message"] for item in unique_findings if item["message"]],
    }

    ssl_payload = {
        "present": bool(present and normalized_summary),
        "summary": normalized_summary,
        "findings": unique_findings,
    }

    return tls_payload, ssl_payload


def normalize_exposures(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    normalized: List[Dict[str, str]] = []
    for finding in findings:
        normalized.append(
            {
                "path": finding.get("path", ""),
                "status": finding.get("status", ""),
                "risk": (finding.get("risk") or "").lower(),
                "detail": finding.get("detail", ""),
            }
        )
    return normalized


def normalize_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def perform_scan(target_url: str) -> Dict[str, Any]:
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid hostname in URL")

    response, final_url = fetch_target(target_url)
    response_headers: Dict[str, str] = {}
    status_code: int | None = None
    body: str | None = None

    if response is not None:
        response_headers = flatten_headers(response.headers)
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

    tls_payload, ssl_payload = normalize_tls(ssl_info)

    formatted_headers = format_security_headers(security_headers)
    tech_payload = normalize_tech_stack(tech_stack)

    normalized_response = {
        "target": target_url,
        "fetched_url": final_url,
        "status_code": status_code,
        "response_headers": normalize_response_headers(response_headers),
        "raw_headers": response_headers,
        "server_ip": server_ip,
        "tech_stack": tech_payload,
        "technology": tech_payload,
        "security_headers": formatted_headers,
        "headers": formatted_headers,
        "tls": tls_payload,
        "ssl": ssl_payload,
        "exposures": normalize_exposures(exposures),
        "risk": {
            "level": risk.get("level", "Unknown"),
            "reasons": risk.get("reasons", []),
        },
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    return normalized_response


@app.post("/scan")
def scan(request: ScanRequest) -> Dict[str, Any]:
    return perform_scan(request.target)


@app.post("/report", response_class=HTMLResponse)
def report(request: ScanRequest) -> HTMLResponse:
    result = perform_scan(request.target)
    html = render_report(result)
    return HTMLResponse(content=html, media_type="text/html")
