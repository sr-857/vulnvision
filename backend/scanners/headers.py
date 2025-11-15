"""Security header auditing utilities for VulnVision."""
from __future__ import annotations

from typing import Dict, List, Literal, Tuple

HeaderStatus = Literal["secure", "needs_review", "missing"]

SECURITY_HEADERS: Dict[str, Dict[str, List[str]]] = {
    "Content-Security-Policy": {
        "bad_substrings": ["unsafe-inline", "unsafe-eval"],
    },
    "X-Frame-Options": {
        "allowed_values": ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "allowed_values": ["nosniff"],
    },
    "Strict-Transport-Security": {
        "requires_https": True,
    },
    "Referrer-Policy": {
        "allowed_values": [
            "no-referrer",
            "no-referrer-when-downgrade",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "same-origin",
        ],
    },
    "Permissions-Policy": {
        "requires_value": True,
    },
}


def classify_header(name: str, value: str | None, is_https: bool) -> Tuple[HeaderStatus, str]:
    """Classify a security header value and return status + note."""
    if value is None:
        return "missing", "Header not present"

    policy = SECURITY_HEADERS.get(name, {})

    if policy.get("requires_https") and not is_https:
        return "needs_review", "Only effective over HTTPS"

    allowed_values = policy.get("allowed_values")
    if allowed_values is not None and value.strip() not in allowed_values:
        return "needs_review", f"Unexpected value `{value}`"

    bad_substrings = policy.get("bad_substrings", [])
    for bad in bad_substrings:
        if bad in value:
            return "needs_review", f"Contains `{bad}`"

    if policy.get("requires_value") and not value.strip():
        return "needs_review", "Header present but empty"

    return "secure", "OK"


def audit_security_headers(
    headers: Dict[str, str], *, is_https: bool
) -> List[Dict[str, str]]:
    """Return a structured assessment for each watched security header."""
    normalized = {k.lower(): v for k, v in headers.items()}
    results: List[Dict[str, str]] = []
    for header in SECURITY_HEADERS:
        value = normalized.get(header.lower())
        status, note = classify_header(header, value, is_https)
        results.append({
            "header": header,
            "value": value,
            "status": status,
            "note": note,
        })
    return results
