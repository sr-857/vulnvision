"""TLS certificate reconnaissance for VulnVision."""

from __future__ import annotations

import datetime as _dt
import socket
import ssl
from typing import Dict, Optional
from urllib.parse import urlparse

USER_AGENT = "VulnVision-TLS/1.0"
DEFAULT_TIMEOUT = 6


def _parse_datetime(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = _dt.datetime.strptime(value, fmt)
            return dt.replace(tzinfo=_dt.timezone.utc).isoformat()
        except ValueError:
            continue
    return value


def _days_remaining(not_after: Optional[str]) -> Optional[int]:
    if not not_after:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = _dt.datetime.strptime(not_after, fmt)
            return (dt - _dt.datetime.utcnow()).days
        except ValueError:
            continue
    return None


def scan_domain(target_url: str) -> Dict[str, object]:
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or 443
    result: Dict[str, object] = {
        "host": hostname or target_url,
        "valid": False,
        "not_before": None,
        "not_after": None,
        "days_to_expire": None,
        "subject": "",
        "issuer": "",
        "key_type": None,
        "key_size": None,
        "signature_algorithm": None,
        "san": [],
        "error": None,
    }

    if not hostname:
        result["error"] = "Hostname missing"
        return result

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        result["error"] = str(exc)
        return result

    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    result["subject"] = ", ".join("=".join(attr) for part in subject for attr in part)
    result["issuer"] = ", ".join("=".join(attr) for part in issuer for attr in part)

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    result["not_before"] = _parse_datetime(not_before)
    result["not_after"] = _parse_datetime(not_after)
    result["days_to_expire"] = _days_remaining(not_after)

    san = []
    for entry in cert.get("subjectAltName", []) or []:
        if entry and entry[0] == "DNS":
            san.append(entry[1])
    result["san"] = san

    result["signature_algorithm"] = cert.get("signatureAlgorithm")
    result["valid"] = result["days_to_expire"] is None or result["days_to_expire"] >= 0

    return result
