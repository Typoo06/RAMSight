# Volatility command construction.

from pathlib import Path

from app.core.config import Settings
from app.volatility.registry import PluginDefinition


def build_volatility_command(
    settings: Settings,
    plugin: PluginDefinition,
    evidence_path: Path,
    output_dir: Path,
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
    if plugin.requires_yara_rules and settings.volatility_yara_rules_path:
        command.extend(["--yara-file", settings.volatility_yara_rules_path])
    command.append(plugin.command_name)
    return command
