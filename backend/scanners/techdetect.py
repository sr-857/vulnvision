"""Technology fingerprinting for VulnVision."""

from __future__ import annotations

from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin

import mmh3
import requests
from bs4 import BeautifulSoup

USER_AGENT = "VulnVision-TechDetect/1.0"

BODY_SIGNATURES: List[tuple[str, List[str], str]] = [
    ("WordPress", ["wp-content", "wp-includes", "wordpress"], "high"),
    ("React", ["data-reactroot", "react/js", "__react_devtools"], "high"),
    ("Angular", ["ng-version", "angular"], "high"),
    ("Vue.js", ["vue.js", "data-v-", "__VUE_DEVTOOLS_GLOBAL_HOOK__"], "medium"),
    ("Next.js", ["__NEXT_DATA__", "_next/static"], "medium"),
    ("Nuxt.js", ["nuxt.config", "__NUXT__"], "medium"),
    ("Django", ["csrftoken", "django"], "medium"),
    ("Laravel", ["window.Laravel", "laravel"], "medium"),
    ("Svelte", ["svelte", "__SVELTE_DEVTOOLS__"], "medium"),
]

HEADER_SIGNATURES: List[tuple[str, List[str], str]] = [
    ("Express.js", ["x-powered-by: express"], "medium"),
    ("Cloudflare", ["server: cloudflare", "cf-ray"], "medium"),
    ("Netlify", ["server: Netlify"], "medium"),
    ("Akamai", ["server: akamai"], "medium"),
    ("Vercel", ["server: vercel"], "medium"),
    ("Fastly", ["server: varnish"], "medium"),
    ("Nginx", ["server: nginx"], "low"),
    ("Apache", ["server: apache"], "low"),
]

FAVICON_SIGNATURES: Dict[int, Tuple[str, str, str]] = {
    -1573933945: ("WordPress", "high", "favicon hash match"),
    -2103118421: ("Cloudflare", "medium", "favicon hash match"),
    -640077903: ("GitHub Pages", "medium", "favicon hash match"),
    -512005670: ("Wix", "medium", "favicon hash match"),
    -783094257: ("React", "medium", "favicon hash match"),
    1549656471: ("Angular", "medium", "favicon hash match"),
    462433723: ("Vercel", "medium", "favicon hash match"),
}


def _record(technologies: List[Dict[str, str]], seen: Set[Tuple[str, str]], name: str, confidence: str, evidence: str) -> None:
    key = (name.lower(), evidence)
    if key in seen:
        return
    technologies.append(
        {
            "name": name,
            "confidence": confidence.title(),
            "evidence": evidence,
        }
    )
    seen.add(key)


def _favicon_candidates(soup: BeautifulSoup, base_url: str) -> List[str]:
    candidates: List[str] = []
    for link in soup.find_all("link", attrs={"rel": True}):
        rels = {rel.lower() for rel in link.get("rel", []) if isinstance(rel, str)}
        if rels & {"icon", "shortcut", "shortcut icon", "apple-touch-icon"}:
            href = link.get("href")
            if href:
                candidates.append(urljoin(base_url, href))
    candidates.append(urljoin(base_url, "/favicon.ico"))
    deduped: List[str] = []
    seen: Set[str] = set()
    for href in candidates:
        if href in seen:
            continue
        seen.add(href)
        deduped.append(href)
    return deduped[:3]


def scan_domain(target_url: str) -> Dict[str, object]:
    result: Dict[str, object] = {"host": target_url, "technologies": []}

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        response = session.get(target_url, timeout=8)
    except requests.RequestException:
        return result

    body_lower = response.text.lower()
    headers_lower = {f"{k.lower()}: {v.lower()}" for k, v in response.headers.items()}
    soup = BeautifulSoup(response.text, "html.parser")

    seen: Set[Tuple[str, str]] = set()
    technologies = result["technologies"]  # alias

    # Body signatures
    for name, patterns, confidence in BODY_SIGNATURES:
        if any(pattern.lower() in body_lower for pattern in patterns):
            _record(technologies, seen, name, confidence, f"Detected pattern: {patterns[0]}")

    # Header signatures
    for name, patterns, confidence in HEADER_SIGNATURES:
        for pattern in patterns:
            if pattern.lower() in headers_lower:
                _record(technologies, seen, name, confidence, pattern)
                break

    # Meta generator tag
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        content = generator["content"].strip()
        _record(technologies, seen, "Generator", "medium", content)
        if "wordpress" in content.lower():
            _record(technologies, seen, "WordPress", "high", f"Generator meta: {content}")

    # Script src hints
    for script in soup.find_all("script", src=True):
        src = script["src"].lower()
        if "wp-content" in src:
            _record(technologies, seen, "WordPress", "high", src)
        if "static/js/bundle.js" in src and "wp-" not in src:
            _record(technologies, seen, "React", "medium", src)
        if "angular" in src:
            _record(technologies, seen, "Angular", "medium", src)

    # Cookies
    for header_name, header_value in response.headers.items():
        if header_name.lower() == "set-cookie" and "wordpress_logged_in" in header_value:
            _record(technologies, seen, "WordPress", "high", "set-cookie: wordpress_logged_in")

    # Favicon hashing
    for icon_url in _favicon_candidates(soup, target_url):
        try:
            icon_resp = session.get(icon_url, timeout=5)
            icon_resp.raise_for_status()
        except requests.RequestException:
            continue
        try:
            hash_value = mmh3.hash(icon_resp.content)
        except Exception:
            continue
        if hash_value in FAVICON_SIGNATURES:
            name, confidence, evidence = FAVICON_SIGNATURES[hash_value]
            _record(technologies, seen, name, confidence, f"{evidence}: {icon_url}")
            break

    # Fallback: server header if nothing detected
    if not technologies and "server" in response.headers:
        _record(technologies, seen, "Server", "low", f"server: {response.headers['server']}")

    return result
