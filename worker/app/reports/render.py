# HTML report rendering with Jinja autoescaping.

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TECHNICAL_REPORT_TEMPLATE = "technical_report.html.j2"


def jinja_environment(templates_dir: str | Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(enabled_extensions=("html", "j2"), default_for_string=True, default=True),
    )


def render_technical_report(context: dict, templates_dir: str | Path) -> str:
    template = jinja_environment(templates_dir).get_template(TECHNICAL_REPORT_TEMPLATE)
    return template.render(**context)


def write_technical_report(path: Path, context: dict, templates_dir: str | Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_technical_report(context, templates_dir), encoding="utf-8")
