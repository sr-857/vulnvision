"""Report generation utilities using Jinja2 templates."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

def _environment() -> Environment:
    loader = FileSystemLoader(str(TEMPLATES_DIR))
    return Environment(
        loader=loader,
        autoescape=select_autoescape(["html", "xml"]),
    )

def render_report(context: Dict[str, Any]) -> str:
    env = _environment()
    template = env.get_template("report.html")
    return template.render(**context)
