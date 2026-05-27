# YARA rule discovery for Volatility memory scanning.

from pathlib import Path

from app.core.config import Settings

YARA_RULE_EXTENSIONS = {".yar", ".yara"}


def list_yara_rule_files(rules_dir: str | Path) -> list[Path]:
    yara_dir = Path(rules_dir) / "yara"
    if not yara_dir.is_dir():
        return []
    return sorted(path for path in yara_dir.iterdir() if path.is_file() and path.suffix.lower() in YARA_RULE_EXTENSIONS)


def list_yara_files_in_directory(directory: str | Path) -> list[Path]:
    path = Path(directory)
    if not path.is_dir():
        return []
    return sorted(item for item in path.iterdir() if item.is_file() and item.suffix.lower() in YARA_RULE_EXTENSIONS)


def resolve_yara_rules_path(settings: Settings) -> Path | None:
    if settings.volatility_yara_rules_path:
        configured_path = Path(settings.volatility_yara_rules_path)
        if configured_path.is_file():
            return configured_path
        configured_rule_files = list_yara_files_in_directory(configured_path)
        return configured_rule_files[0] if configured_rule_files else None
    rules_dir = getattr(settings, "rules_dir", None)
    if not rules_dir:
        return None
    rule_files = list_yara_rule_files(rules_dir)
    return rule_files[0] if rule_files else None
