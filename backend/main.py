import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import Response

from scanners import exposure, headers as headers_scanner, sslscan, techdetect
from utils import report as report_utils

APP_TITLE = "VulnVision - Backend (UI contract)"
IMPORTANT_HEADERS: List[str] = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

app = FastAPI(title=APP_TITLE)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str


def normalize_target(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError("target required")
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}"


def dedupe(sequence: List[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in sequence:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def classify_exposure(entry: Dict[str, Any]) -> str:
    path = entry.get("path", "")
    status = entry.get("status")
    high_paths = {"/.git/", "/.env", "/backup.zip", "/config.php"}
    if status in (200, 301, 302) and path in high_paths:
        return "high"
    if path == "/robots.txt" and status == 200:
        return "medium"
    if status in (401, 403):
        return "low"
    if status == 200 and path == "/admin":
        return "medium"
    return "low"


async def perform_scan(raw_target: str) -> Dict[str, Any]:
    url = normalize_target(raw_target)

    try:
        headers_res, ssl_res, tech_res, exposure_res = await asyncio.gather(
            asyncio.to_thread(headers_scanner.scan_domain, url),
            asyncio.to_thread(sslscan.scan_domain, url),
            asyncio.to_thread(techdetect.scan_domain, url),
            asyncio.to_thread(exposure.scan_domain, url),
        )
    except Exception as exc:  # pragma: no cover - safety net
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    raw_headers = headers_res.get("headers") or {}
    lowered_headers = {k.lower(): v for k, v in raw_headers.items()}

    header_rows: List[Dict[str, Any]] = []
    risk_reasons: List[str] = []
    for header_name in IMPORTANT_HEADERS:
        value = raw_headers.get(header_name)
        if value is None:
            value = lowered_headers.get(header_name.lower())
        status = "missing"
        note = "Header not present"
        if header_name in headers_res.get("present_headers", []):
            status = "secure"
            note = ""
        elif value:
            status = "needs_review"
            note = "Unexpected value"
        if status == "missing":
            risk_reasons.append(f"Missing security header: {header_name}")
        elif status == "needs_review":
            risk_reasons.append(f"Header needs review: {header_name}")
        header_rows.append(
            {
                "header": header_name,
                "status": status,
                "value": value or "—",
                "note": note,
            }
        )

    exposures: List[Dict[str, Any]] = []
    for entry in exposure_res.get("exposures", []):
        path = entry.get("path", "")
        status_code = entry.get("status")
        detail = entry.get("detail", "")
        risk = classify_exposure(entry)
        if risk in ("high", "medium"):
            descriptor = detail or "exposed path"
            risk_reasons.append(f"Exposure: {path} — {descriptor}")
        exposures.append(
            {
                "path": path,
                "status": status_code,
                "risk": risk,
                "detail": detail,
            }
        )

    tls_findings: List[str] = []
    days_remaining = ssl_res.get("days_to_expire")
    if isinstance(days_remaining, int) and days_remaining < 45:
        tls_findings.append(f"Certificate expires within {days_remaining} days")
        risk_reasons.append(f"TLS certificate expires within {days_remaining} days")
    if not ssl_res.get("valid", False):
        tls_findings.append("Certificate validation failed or is expired")
        risk_reasons.append("TLS: certificate invalid or expired")
    if ssl_res.get("error"):
        tls_findings.append(ssl_res["error"])

    tls_payload: Dict[str, Any] = {
        "subject": ssl_res.get("subject", ""),
        "issuer": ssl_res.get("issuer", ""),
        "valid_from": ssl_res.get("not_before"),
        "valid_to": ssl_res.get("not_after"),
        "days_remaining": days_remaining,
        "key_type": ssl_res.get("key_type"),
        "key_size": ssl_res.get("key_size"),
        "signature": ssl_res.get("signature_algorithm"),
        "san": ssl_res.get("san", []),
        "valid": ssl_res.get("valid", False),
        "findings": tls_findings,
    }

    ssl_payload = {
        "present": bool(tls_payload["subject"] or tls_payload["issuer"]),
        "summary": {
            "subject": tls_payload["subject"],
            "issuer": tls_payload["issuer"],
            "not_before": tls_payload["valid_from"],
            "not_after": tls_payload["valid_to"],
            "days_remaining": tls_payload["days_remaining"],
            "signature_algorithm": tls_payload["signature"],
            "key_type": tls_payload["key_type"],
            "key_size": tls_payload["key_size"],
            "san": tls_payload["san"],
        },
        "findings": [
            {"message": message, "severity": "medium"} for message in tls_findings
        ],
    }

    tech_payload: List[Dict[str, Any]] = []
    for item in tech_res.get("technologies", []):
        if isinstance(item, dict):
            name = item.get("name", "Unknown")
            confidence = item.get("confidence", "medium")
            evidence = item.get("evidence", "")
        else:
            name = str(item)
            confidence = "medium"
            evidence = ""
        tech_payload.append(
            {
                "name": name,
                "confidence": confidence.title(),
                "evidence": evidence,
            }
        )

    missing_headers = sum(1 for header in header_rows if header["status"] == "missing")
    high_exposures = sum(1 for exposure_entry in exposures if exposure_entry["risk"] == "high")
    score = missing_headers + high_exposures * 2
    if not ssl_res.get("valid", False):
        score += 2

    if score >= 4:
        risk_level = "High"
    elif score >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    risk_reasons = dedupe(risk_reasons)
    if not risk_reasons:
        risk_reasons = ["No significant issues detected"]

    response_payload: Dict[str, Any] = {
        "target": raw_target,
        "fetched_url": url,
        "status_code": headers_res.get("status_code"),
        "response_headers": {k.lower(): v for k, v in raw_headers.items()},
        "raw_headers": raw_headers,
        "technology": tech_payload,
        "tech_stack": tech_payload,
        "headers": header_rows,
        "security_headers": header_rows,
        "tls": tls_payload,
        "ssl": ssl_payload,
        "exposures": exposures,
        "risk": {
            "level": risk_level,
            "reasons": risk_reasons,
        },
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    return response_payload


@app.post("/scan")
async def scan(request: ScanRequest) -> Dict[str, Any]:
    try:
        return await perform_scan(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/report")
async def report(request: ScanRequest) -> Response:
    try:
        data = await perform_scan(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    html = report_utils.render_html(data)
    return Response(content=html, media_type="text/html")
