# Detection rule and scoring configuration loader.

from pathlib import Path
from typing import Any

import yaml

from app.detection.rules import DetectionRule, rule_from_dict


class RulesLoadError(ValueError):
    pass


def load_yaml_file(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RulesLoadError(f"invalid YAML in {path.name}") from exc
    if not isinstance(payload, dict):
        raise RulesLoadError(f"YAML document must be a mapping: {path.name}")
    return payload


def load_detection_rules(rules_dir: str | Path) -> list[DetectionRule]:
    detection_dir = Path(rules_dir) / "detection"
    if not detection_dir.is_dir():
        raise RulesLoadError("detection rules directory is missing")

    rules: list[DetectionRule] = []
    for path in sorted(detection_dir.glob("*.yaml")):
        payload = load_yaml_file(path)
        raw_rules = payload.get("rules") or []
        if not isinstance(raw_rules, list):
            raise RulesLoadError(f"rules must be a list: {path.name}")
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict):
                raise RulesLoadError(f"rule entry must be a mapping: {path.name}")
            try:
                rules.append(rule_from_dict(raw_rule))
            except ValueError as exc:
                raise RulesLoadError(f"{path.name}: {exc}") from exc
    return rules


def load_risk_scoring_config(rules_dir: str | Path) -> dict[str, Any]:
    scoring_path = Path(rules_dir) / "risk_scoring" / "default_score.yaml"
    if not scoring_path.is_file():
        raise RulesLoadError("risk scoring configuration is missing")
    return load_yaml_file(scoring_path)
