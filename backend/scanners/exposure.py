"""Passive exposure probes for VulnVision."""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin

import requests

COMMON_CHECKS: List[tuple[str, str]] = [
    ("/.git/", "Git repository exposed"),
    ("/.git/config", "Git configuration exposed"),
    ("/.svn/", "SVN repository exposed"),
    ("/.hg/", "Mercurial repository exposed"),
    ("/.env", "Environment file exposed"),
    ("/.aws/credentials", "AWS credentials exposed"),
    ("/.ssh/id_rsa", "Private SSH key exposed"),
    ("/.bash_history", "Command history exposed"),
    ("/.DS_Store", "macOS metadata exposed"),
    ("/backup.zip", "Backup archive accessible"),
    ("/db.sql", "Database dump accessible"),
    ("/database.sql", "Database dump accessible"),
    ("/config.php", "PHP configuration exposed"),
    ("/web.config", "IIS configuration exposed"),
    ("/phpinfo.php", "phpinfo() endpoint exposed"),
    ("/server-status", "Apache server status exposed"),
    ("/server-info", "Apache server info exposed"),
    ("/admin", "Admin portal"),
    ("/admin/login", "Administrative login"),
    ("/wp-admin", "WordPress admin interface"),
    ("/wp-login.php", "WordPress login page"),
    ("/cgi-bin/", "CGI scripts exposed"),
    ("/api/docs", "API documentation exposed"),
    ("/swagger-ui.html", "Swagger UI exposed"),
    ("/grafana/login", "Grafana login exposed"),
    ("/kibana", "Kibana interface exposed"),
    ("/metrics", "Prometheus metrics exposed"),
    ("/actuator", "Spring Boot actuator exposed"),
    ("/debug", "Debug endpoint exposed"),
    ("/uploads/", "Public uploads directory"),
    ("/storage/", "Storage directory exposed"),
    ("/vendor/", "Dependency directory exposed"),
    ("/node_modules/", "Node modules accessible"),
    ("/robots.txt", "robots.txt reveals sensitive paths"),
]

USER_AGENT = "VulnVision-Exposure/1.0"


def scan_domain(target_url: str) -> Dict[str, object]:
    result: Dict[str, object] = {"host": target_url, "exposures": []}

    for path, note in COMMON_CHECKS:
        url = urljoin(target_url, path)
        try:
            response = requests.get(url, timeout=4, allow_redirects=False, headers={"User-Agent": USER_AGENT})
        except requests.RequestException:
            continue

        entry: Dict[str, object] = {
            "path": path,
            "status": response.status_code,
            "detail": note,
        }

        if response.status_code == 200:
            result["exposures"].append(entry)
        elif response.status_code in (301, 302) and path in {"/admin", "/admin/login", "/wp-admin"}:
            entry["detail"] = f"{note} (redirect)"
            result["exposures"].append(entry)

    return result
