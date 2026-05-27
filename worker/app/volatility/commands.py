# Volatility command construction.

from pathlib import Path

from app.core.config import Settings
from app.volatility.registry import PluginDefinition


def build_volatility_command(
    settings: Settings,
    plugin: PluginDefinition,
    evidence_path: Path,
    output_dir: Path,
    yara_rules_path: Path | str | None = None,
) -> list[str]:
    _ = output_dir
    command = [
        settings.volatility_path,
        "-f",
        str(evidence_path),
        "-q",
        "-r",
        "json",
    ]
    if settings.volatility_symbol_path:
        command.extend(["-s", settings.volatility_symbol_path])
    command.append(plugin.command_name)
    selected_yara_rules = yara_rules_path or settings.volatility_yara_rules_path
    if plugin.requires_yara_rules and selected_yara_rules:
        command.extend(["--yara-file", str(selected_yara_rules)])
    return command
