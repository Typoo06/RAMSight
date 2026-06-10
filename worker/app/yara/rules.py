# YARA rule discovery for Volatility memory scanning.

import json
from pathlib import Path

from app.core.config import Settings

YARA_RULE_EXTENSIONS = {".yar", ".yara"}
PROFILE_YARA_PACKS = {
    "windows_memory_yara": "elastic_yara",
    "windows_memory_yara_elastic": "elastic_yara",
    "windows_memory_yara_neo23x0": "neo23x0_yara",
    "windows_memory_yara_third_party_all": "third_party_yara_all",
    "windows_memory_deep_yara_elastic": "elastic_yara",
    "windows_memory_deep_yara_neo23x0": "neo23x0_yara",
    "windows_memory_deep_yara_third_party_all": "third_party_yara_all",
}
HEAVY_YARA_PROFILES = {
    "windows_memory_yara_third_party_all",
    "windows_memory_deep_yara_third_party_all",
}


def list_yara_rule_files(rules_dir: str | Path) -> list[Path]:
    yara_dir = Path(rules_dir) / "yara"
    if not yara_dir.is_dir():
        return []
    compiled_dir = yara_dir / "compiled"
    if compiled_dir.is_dir():
        return sorted(path for path in compiled_dir.iterdir() if path.is_file() and path.suffix.lower() in YARA_RULE_EXTENSIONS)
    return []


def list_yara_files_in_directory(directory: str | Path) -> list[Path]:
    path = Path(directory)
    if not path.is_dir():
        return []
    return sorted(item for item in path.iterdir() if item.is_file() and item.suffix.lower() in YARA_RULE_EXTENSIONS)


def yara_pack_for_profile(plugin_profile: str | None) -> str | None:
    return PROFILE_YARA_PACKS.get((plugin_profile or "").strip().lower())


def profile_uses_yara(plugin_profile: str | None) -> bool:
    return yara_pack_for_profile(plugin_profile) is not None


def profile_is_heavy_yara(plugin_profile: str | None) -> bool:
    return (plugin_profile or "").strip().lower() in HEAVY_YARA_PROFILES


def compiled_yara_pack_path(settings: Settings, pack_name: str) -> Path:
    return Path(settings.rules_dir) / "yara" / "compiled" / f"{pack_name}.yar"


def compiled_yara_pack_manifest_path(settings: Settings, pack_name: str) -> Path:
    return Path(settings.rules_dir) / "yara" / "compiled" / f"{pack_name}.manifest.json"


def load_yara_pack_rule_metadata(settings: Settings, pack_name: str | None) -> dict[str, dict]:
    if not pack_name:
        return {}
    manifest_path = compiled_yara_pack_manifest_path(settings, pack_name)
    if not manifest_path.is_file():
        return {}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    rules = payload.get("rules")
    if not isinstance(rules, dict):
        return {}
    return {str(rule_name).lower(): metadata for rule_name, metadata in rules.items() if isinstance(metadata, dict)}


def resolve_yara_rules_path(settings: Settings, plugin_profile: str | None = None) -> Path | None:
    profile_pack = yara_pack_for_profile(plugin_profile)
    if profile_pack:
        pack_path = compiled_yara_pack_path(settings, profile_pack)
        return pack_path if pack_path.is_file() else None

    rules_dir = getattr(settings, "rules_dir", None)
    if settings.volatility_yara_rules_path:
        configured_path = Path(settings.volatility_yara_rules_path)
        disabled_parts = {"disabled", "archive"}
        if disabled_parts & set(configured_path.parts):
            return None
        if configured_path.is_file():
            return configured_path
        if not configured_path.is_absolute() and rules_dir:
            rules_root = Path(rules_dir)
            candidate_paths = [
                rules_root / configured_path,
                rules_root.parent / configured_path,
            ]
            for candidate in candidate_paths:
                if disabled_parts & set(candidate.parts):
                    continue
                if candidate.is_file():
                    return candidate
        configured_rule_files = list_yara_files_in_directory(configured_path)
        return configured_rule_files[0] if configured_rule_files else None
    if not rules_dir:
        return None
    rule_files = list_yara_rule_files(rules_dir)
    return rule_files[0] if rule_files else None
