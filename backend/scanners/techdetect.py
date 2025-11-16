"""Technology fingerprinting for VulnVision."""

from __future__ import annotations

from typing import Dict, List

import requests

SIGNATURES: List[tuple[str, List[str]]] = [
    ("WordPress", ["wp-content", "wp-includes", "wordpress"]),
    ("React", ["data-reactroot", "react/js", "main-es2015"]),
    ("Angular", ["ng-version", "angular"]),
    ("Express.js", ["x-powered-by: express", "express"]),
    ("Cloudflare", ["server: cloudflare", "cf-ray"]),
]

USER_AGENT = "VulnVision-TechDetect/1.0"


def scan_domain(target_url: str) -> Dict[str, object]:
    result: Dict[str, object] = {"host": target_url, "technologies": []}

    try:
        response = requests.get(target_url, timeout=6, headers={"User-Agent": USER_AGENT})
    except requests.RequestException:
        return result

    body = response.text.lower()
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}

    for name, patterns in SIGNATURES:
        for pattern in patterns:
            pattern_lower = pattern.lower()
            evidence = ""
            if pattern_lower in body:
                evidence = pattern
            else:
                for header_name, header_value in headers.items():
                    if pattern_lower in f"{header_name}: {header_value}":
                        evidence = f"{header_name}: {header_value}"
                        break
            if evidence:
                confidence = "high" if name in {"WordPress", "React", "Angular"} else "medium"
                result["technologies"].append(
                    {
                        "name": name,
                        "confidence": confidence,
                        "evidence": evidence,
                    }
                )
                break

    return result
