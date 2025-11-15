"""SSL/TLS certificate analysis utilities for VulnVision."""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

SSL_PORT = 443


@dataclass
class CertificateFinding:
    message: str
    severity: str


@dataclass
class CertificateSummary:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    days_remaining: int
    signature_algorithm: str
    key_type: str
    key_size: Optional[int]
    san: List[str]


def _load_certificate(binary_cert: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(binary_cert)


def _format_name(name: x509.Name) -> str:
    return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)


def _extract_san(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [entry.value for entry in ext.value.get_values_for_type(x509.DNSName)]


def fetch_certificate(hostname: str, port: int = SSL_PORT) -> Optional[bytes]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                return tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None


def analyze_certificate(hostname: str) -> Dict[str, object]:
    binary_cert = fetch_certificate(hostname)
    if not binary_cert:
        return {
            "present": False,
            "summary": None,
            "findings": [
                CertificateFinding(
                    message="Unable to retrieve certificate (host may not support HTTPS)",
                    severity="high",
                ).__dict__
            ],
        }

    cert = _load_certificate(binary_cert)
    subject = _format_name(cert.subject)
    issuer = _format_name(cert.issuer)
    san = _extract_san(cert)

    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_remaining = int((not_after - now).total_seconds() // 86400)

    public_key = cert.public_key()
    key_type = type(public_key).__name__
    key_size = getattr(public_key, "key_size", None)

    signature_algorithm = "Unknown"
    if cert.signature_algorithm_oid is not None:
        signature_algorithm = cert.signature_algorithm_oid._name or str(
            cert.signature_algorithm_oid
        )

    summary = CertificateSummary(
        subject=subject,
        issuer=issuer,
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        days_remaining=days_remaining,
        signature_algorithm=signature_algorithm,
        key_type=key_type,
        key_size=key_size,
        san=san,
    )

    findings: List[CertificateFinding] = []
    if days_remaining < 0:
        findings.append(
            CertificateFinding("Certificate has expired", "high")
        )
    elif days_remaining < 14:
        findings.append(
            CertificateFinding("Certificate expires within 14 days", "medium")
        )

    if key_type == rsa.RSAPublicKey.__name__ and key_size and key_size < 2048:
        findings.append(
            CertificateFinding(
                f"RSA key size is weak ({key_size} bits)", "high"
            )
        )

    try:
        ssl.match_hostname({"subjectAltName": [("DNS", name) for name in san]}, hostname)
    except ssl.CertificateError:
        findings.append(
            CertificateFinding("Certificate SAN does not match hostname", "high")
        )

    # Warn for old signature algorithms
    weak_signatures = {hashes.MD5.name.lower(), hashes.SHA1.name.lower()}
    if signature_algorithm and signature_algorithm.lower() in weak_signatures:
        findings.append(
            CertificateFinding(
                f"Weak signature algorithm in use ({signature_algorithm})", "high"
            )
        )

    return {
        "present": True,
        "summary": summary.__dict__,
        "findings": [f.__dict__ for f in findings],
    }
