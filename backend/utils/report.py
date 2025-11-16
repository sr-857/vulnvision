"""HTML report rendering utilities."""
from __future__ import annotations

import os
from typing import Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(HERE, "..", "templates")

env = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=select_autoescape(["html", "xml"]),
)


def render_html(data: Dict) -> str:
    template = env.get_template("report.html")
    return template.render(data=data)
